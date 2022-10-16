// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Implementation a cross-chain messaging system for Axelar.
///
/// This code is based on the following:
///
/// - When message is sent to Sui, it targets an object and not a module;
/// - To support cross-chain messaging, a Channel object has to be created;
/// - Channel can be either owned or shared but not frozen;
/// - Module developer on the Sui side will have to implement a system to support messaging;
/// - Checks for uniqueness of messages should be done through `Channel`s to avoid big data storage;
///
/// I. Sending messages
///
/// A message is sent through the `send` function, a Channel is supplied to determine the source -> ID.
/// Event is then emitted and Axelar network can operate
///
/// II. Receiving messages
///
/// Message bytes and signatures are passed into `create` function to generate a Message object.
///  - Signatures are checked against the known set of validators.
///  - Message bytes are parsed to determine: source, destination_chain, payload and target_id
///  - `target_id` points to a `Channel` object
///
/// Once created, `Message` needs to be consumed. And the only way to do it is by calling
/// `consume_message` function and pass a correct `Channel` instance alongside the `Message`.
///  - Message is checked for uniqueness (for this channel)
///  - Message is checked to match the `Channel`.id
///
module axelar::messenger {
    use sui::object::{Self, UID};
    use sui::vec_set::{Self, VecSet};
    use sui::tx_context::{TxContext};
    use sui::vec_map::{VecMap};
    use sui::ecdsa;

    use std::vector as vec;

    // Temp use a local version of BCS
    use axelar::bcs;

    /// For when trying to consume the wrong object.
    const EWrongDestination: u64 = 0;

    /// For when message signatures failed verification.
    const ESignatureInvalid: u64 = 1;

    /// For when message has already been processed and submitted twice.
    const EDuplicateMessage: u64 = 2;

    /// For when message chainId is not SUI.
    const EInvalidChain: u64 = 3;

    /// For when number of commands does not match number of command ids.
    const EInvalidCommands: u64 = 4;

    /// Used for a check in `validate_proof` function.
    const OLD_KEY_RETENTION: u64 = 16;


    // TODO: decide fate for these pals
    // const SELECTOR_BURN_TOKEN: vector<u8> = b"burnToken";
    // const SELECTOR_DEPLOY_TOKEN: vector<u8> = b"deployToken";
    // const SELECTOR_MINT_TOKEN: vector<u8> = b"mintToken";

    // These are currently supported
    const SELECTOR_APPROVE_CONTRACT_CALL: vector<u8> = b"approveContractCall";
    const SELECTOR_APPROVE_CONTRACT_CALL_WITH_MINT: vector<u8> = b"approveContractCallWithMint";
    const SELECTOR_TRANSFER_OPERATORSHIP: vector<u8> = b"transferOperatorship";

    /// Mocking this for now until actual implementation of validator management.
    /// Nevertheless it will be a shared / frozen object accessible to everyone
    /// on the network.
    ///
    /// Perhaps, its implementation should be moved to a different module which
    /// will implement messenger interface for the `Validators` object.
    struct Validators has key {
        id: UID,
        epoch: u64,
        epoch_for_hash: VecMap<vector<u8>, u64>
    }

    /// Generic target for the messaging system.
    ///
    /// This struct is required on the Sui side to be the destination for the
    /// messages sent from other chains. Even though it has a UID field, it does
    /// not have a `key` ability to force wrapping.
    ///
    /// Notes:
    ///
    /// - Does not have key to prevent 99% of the mistakes related to access management.
    /// Also prevents arbitrary Message destruction if the object is shared. Lastly,
    /// when shared, `Channel` cannot be destroyed, and its contents will remain locked
    /// forever.
    ///
    /// - Allows asset or capability-locking inside. Some applications might
    /// authorize admin actions through the bridge (eg by locking some `AdminCap`
    /// inside and getting a `&mut AdminCap` in the `consume_message`);
    ///
    /// - Can be destroyed freely as the `UID` is guaranteed to be unique across
    /// the system. Destroying a channel would mean the end of the Channel cycle
    /// and all further messages will have to target a new Channel if there is one.
    ///
    /// - Does not contain direct link to the state in Sui, as some functions
    /// might not take any specific data (eg allow users to create new objects).
    /// If specific object on Sui is targeted by this `Channel`, its reference
    /// should be implemented using the `data` field.
    ///
    /// - The funniest and extremely simple implementation would be a `Channel<ID>`
    /// since it actually contains the data required to point at the object in Sui.
    struct Channel<T: store> has store {
        /// Unique ID of the target object which allows message targeting
        /// by comparing against `id_bytes`.
        id: UID,
        /// Messages processed by this object. To make system less
        /// centralized, and spread the storage + io costs across multiple
        /// destinations, we can track every `Channel`'s messages.
        messages: VecSet<vector<u8>>,
        /// Additional field to optionally use as metadata for the Channel
        /// object improving identification and uniqueness of data.
        /// Can store any struct that has `store` ability (including other
        /// objects - eg Capabilities).
        data: T
    }

    /// Message object which can consumed only by a `Channel` object.
    /// Does not require additional generic field to operate as linking
    /// by `id_bytes` is more than enough.
    struct Message has key, store {
        id: UID,
        /// ID of the message, guaranteed to be unique by Axelar.
        msg_id: vector<u8>,
        /// The target Channel's UID.
        target_id: address,
        /// Name of the chain where this message came from.
        source_chain: vector<u8>,
        /// Address of the source chain (vector used for compatibility).
        source_address: vector<u8>,
        /// Hash of the full payload (including source_* fields).
        payload_hash: vector<u8>,
        /// The rest of the payload to be used by the application.
        payload: vector<u8>,
    }

    /// Emitted when a new message is sent from the SUI network.
    struct MessageSent has copy, drop {
        source: vector<u8>,
        destination: vector<u8>,
        destination_address: vector<u8>,
        payload: vector<u8>,
    }

    /// Create new `Channel<T>` object. Anyone can create their own `Channel` to target
    /// from the outside and there's no limitation to the data stored inside it.
    ///
    /// `copy` ability is required to disallow asset locking inside the `Channel`.
    public fun create_channel<T: store>(t: T, ctx: &mut TxContext): Channel<T> {
        Channel {
            id: object::new(ctx),
            messages: vec_set::empty(),
            data: t
        }
    }

    /// Destroy a `Channel<T>` releasing the T. Not constrained and can be performed
    /// by any party as long as they own a Channel.
    public fun destroy_channel<T: store>(self: Channel<T>): T {
        let Channel { id, messages: _, data } = self;
        object::delete(id);
        data
    }

    /// Main entrypoint for the messaging protocol.
    /// Processes the data and the signatures generating a vector of ]
    /// `Message` objects.
    ///
    /// Aborts with multiple error codes, ignores messages which are not
    /// supported by the current implementation of the protocol.
    ///
    /// Input data must be serialized with BCS (see specification
    /// here: https://github.com/diem/bcs).
    public fun create_messages(
        input: vector<u8>,
        ctx: &mut TxContext
    ): vector<Message> {
        let (data, proof) = (
            bcs::peel_vec_u8(&mut input),
            bcs::peel_vec_u8(&mut input)
        );

        let message_hash = ecdsa::keccak256(&data);
        let _allow_operatorship_transfer = validate_proof(message_hash, proof);

        let (chain_id, command_ids, commands, params) = (
            bcs::peel_u64(&mut data),
            bcs::peel_vec_vec_u8(&mut data),
            bcs::peel_vec_vec_u8(&mut data),
            bcs::peel_vec_vec_u8(&mut data)
        );

        // ... figure out whether it has to be a string ...
        assert!(chain_id == 1, EInvalidChain);

        let (i, commands_len, messages) = (0, vec::length(&commands), vec::empty());

        // make sure number of commands passed matches command IDs
        assert!(vec::length(&command_ids) == commands_len, EInvalidCommands);

        while (i < commands_len) {
            let msg_id = *vec::borrow(&command_ids, i);
            let cmd_selector = vec::borrow(&commands, i);
            let payload = *vec::borrow(&params, i);

            i = i + 1;

            // Build a `Message` object from the `params[i]`. BCS serializes data
            // in order, so field reads have to be done carefully and in order!
            if (cmd_selector == &SELECTOR_APPROVE_CONTRACT_CALL) {
                vec::push_back(&mut messages, Message {
                    id: object::new(ctx),
                    msg_id,

                    source_chain: bcs::peel_vec_u8(&mut payload),
                    source_address: bcs::peel_vec_u8(&mut payload),
                    target_id: bcs::peel_address(&mut payload),
                    payload_hash: bcs::peel_vec_u8(&mut payload),
                    payload
                });
            } else if (cmd_selector == &SELECTOR_APPROVE_CONTRACT_CALL_WITH_MINT) {
                // TODO: remember me, friend
                continue

            } else if (cmd_selector == &SELECTOR_TRANSFER_OPERATORSHIP) {
                // TODO: please, don't forget about me, champ
                continue
            } else {
                continue
            }
        };

        messages
    }

    /// [DEPRECATED]
    /// 
    /// Spawn a message from the passed data and signatures. Data is processed and
    /// used to construct a `Message` struct, and the signatures are checked to be
    /// of current validators from the validator set.
    public fun create_message() { /* Consider removing this function */ }

    /// By using &mut here we make sure that the object is not in the freeze
    /// state and the owner has full access to the target.
    ///
    /// Most common scenario would be to target a shared object, however this
    /// messaging system allows sending private messages which can be consumed
    /// by single-owner targets.
    ///
    /// For Capability-locking, a mutable reference to the `Channel.data` field is
    /// returned; the rest are the fields of the `Message`.
    public fun consume_message<T: store>(
        t: &mut Channel<T>, m: Message
    ): (&mut T, vector<u8>, vector<u8>, vector<u8>, vector<u8>) {
        let Message {
            id,
            msg_id,
            target_id,
            source_chain,
            source_address,
            payload_hash,
            payload
        } = m;

        // TODO: figure out a way to provide unique identifier for the message (payload? signatures? hash contents?)
        assert!(!vec_set::contains(&t.messages, &msg_id), EDuplicateMessage);
        assert!(target_id == object::uid_to_address(&t.id), EWrongDestination);
        object::delete(id);

        (
            &mut t.data,
            source_chain,
            source_address,
            payload_hash,
            payload
        )
    }

    /// Send a message to another chain. Supply the event data and the
    /// destination chain.
    ///
    /// Event data is collected from the Channel (eg ID of the source
    /// and source_chain is a constant).
    public fun send_message<T: store>(
        t: &mut Channel<T>,
        destination: vector<u8>,
        destination_address: vector<u8>,
        payload: vector<u8>
    ) {
        sui::event::emit(MessageSent {
            source: object::uid_to_bytes(&t.id),
            destination,
            destination_address,
            payload,
        })
    }


    /// Implementation of the `AxelarAuthWeighted.validateProof`.
    /// Does proof validation, fails when proof is invalid or if weight
    /// threshold is not reached.
    fun validate_proof(
        _message_hash: vector<u8>,
        _proof: vector<u8>
    ): bool {
        // turn everything into bcs bytes and merge together
        // let operators_hash = ecdsa::keccak256(bcs::to_bytes(&vector[
        //     bcs::to_bytes(&operators),
        //     bcs::to_bytes(&weights),
        //     bcs::to_bytes(&threshold),
        // ]));

        // let operators_length = vec::length(&operators);
        // let operators_epoch = *vec_map::get(&validators.epoch_for_hash, &operators_hash);
        // let epoch = validators.epoch;

        // assert!(operators_epoch != 0 && epoch - operators_epoch < OLD_KEY_RETENTION, 0); // EInvalidOperators

        // // _validateSignatures() implementation
        // let (i, weight, operator_index) = (0, 0, 0);
        // let total_signatures = vec::length(&signatures);

        // while (i < total_signatures) {
        //     let signed_by = ecdsa::ecrecover(*vec::borrow(&signatures, i), *&hash);
        //     while (operator_index < operators_length && &signed_by != &bcs::to_bytes(vec::borrow(&operators, operator_index))) {
        //         operator_index = operator_index + 1;
        //     };

        //     assert!(operator_index == operators_length, 0); // EMalformedSigners

        //     weight = weight + *vec::borrow(&weights, operator_index);
        //     if (weight >= threshold) { return true };
        //     operator_index = operator_index + 1;
        // };

        // abort 0 // ELowSignaturesWeight
        true
    }

    // Test message for the `test_execute` test.
    // Generated via the `presets` script.
    #[test_only]
    const MESSAGE: vector<u8> = x"900101000000000000000209726f6775655f6f6e650a6178656c61725f74776f0210646f5f736f6d657468696e675f66756e0b646f5f69745f616761696e02270345544803307830e46c640828a7e9277c0035d90332edf9ed18bf9304000000000500000000002a064158454c415203307831e46c640828a7e9277c0035d90332edf9ed18bf93040000000005000000000006010203040506";

    #[test_only]
    /// Handy method for burning `vector<Message>` returned by the `execute` function.
    fun delete_messages(msgs: vector<Message>) {
        while (vec::length(&msgs) > 0) {
            let Message {
                id,
                msg_id: _,
                target_id: _,
                source_chain: _,
                source_address: _,
                payload_hash: _,
                payload: _
            } = vec::pop_back(&mut msgs);
            object::delete(id);
        };
        vec::destroy_empty(msgs);
    }

    #[test] fun test_execute() {
        use sui::test_scenario::{Self as ts, ctx};

        let scenario = ts::begin(@0x0);
        let messages = create_messages(MESSAGE, ctx(&mut scenario));

        delete_messages(messages);

        ts::end(scenario);
    }
}

#[test_only]
module axelar::messenger_tests {
    // use std::vector as v;
    // use axelar::bcs;


}
