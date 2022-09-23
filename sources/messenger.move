// Copyright (c) 2022, Mysten Labs, Inc.
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
/// Once created, `Message` needs to be consumed. And the only way to do it is by calling `consume`
/// function and pass a correct `Channel` instance alongside the `Message`.
///  - Message is checked for uniqueness (for this channel)
///  - Message is checked to match the `Channel`.id
///
module axelar::messenger {
    use sui::object::{Self, UID};
    use sui::vec_set::{Self, VecSet};
    use sui::tx_context::{TxContext};
    use sui::vec_map::{Self, VecMap};
    use sui::crypto;

    use std::hash::sha3_256;
    use std::vector as vec;
    use std::bcs;

    /// For when trying to consume the wrong object.
    const EWrongDestination: u64 = 0;

    /// For when message signatures failed verification.
    const ESignatureInvalid: u64 = 1;

    /// For when message has already been processed and submitted twice.
    const EDuplicateMessage: u64 = 2;

    /// Used for a check in `validate_proof` function.
    const OLD_KEY_RETENTION: u64 = 16;

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
    /// This object is required on the Sui side to be the destination for the
    /// messages sent from other chains.
    ///
    /// Notes:
    ///
    /// - `drop` ability is a requirement to prevent asset-locking inside a
    /// Channel (ie someone can lock Coin or something else).
    ///
    /// Note to self: what if a one-time-witness was locked here? It falls into
    /// the `drop` + `store` category...
    ///
    /// - It is impossible to remove this object in favor of direct usage of
    /// the data as `Channel` also stores all processed messages and provides
    /// uniqueness and guarantees that a single message was processed only once.
    ///
    /// - Does not contain direct link to the state in Sui, as some functions
    /// might not take any specific data (eg allow users to create new objects).
    /// If specific object on Sui is targeted by this `Channel`, its reference
    /// should be implemented using the `data` field.
    ///
    /// - The funniest and extremely simple implementation would be a `Channel<ID>`
    /// since it actually contains the data required to point at the object in Sui.
    struct Channel<T: store + drop> has key, store {
        /// Unique ID of the target object which allows message targeting
        /// by comparing against `id_bytes`.
        id: UID,
        /// Messages processed by this object. To make system less
        /// centralized, and spread the storage + io costs accross multiple
        /// destinations, we can track every `Channel`'s messages.
        messages: VecSet<vector<u8>>,
        /// Additional field to optionally use as metadata for the Channel
        /// object improving identification and uniqueness of data.
        /// Can store any struct that has `store` ability.
        data: T
    }

    /// Message object which can consumed only by a `Channel` object.
    /// Does not require additional generic field to operate as linking
    /// by `id_bytes` is more than enough.
    struct Message has key, store {
        id: UID,
        /// The target object's ID bytes. We have to use ID bytes
        /// here because ID is not constructable, and we build the
        /// destination from raw bytes.
        target_id: vector<u8>,

        /* more fields expected here */
        source: vector<u8>,
        destination: vector<u8>,
        payload: vector<u8>,
    }

    /// Emitted when new message is sent from SUI chain.
    struct MessageSent has copy, drop {
        source: vector<u8>,
        destination: vector<u8>,
        destination_address: vector<u8>,
        payload: vector<u8>,
    }

    /// Access data stored inside a `Channel`.
    public fun channel_data<T: store + drop>(b: &Channel<T>): &T {
        &b.data
    }

    /// Create new `Channel<T>` object. Anyone can create their own `Channel` to target
    /// from the outside and there's no limitation to the data stored inside it.
    ///
    /// `copy` ability is required to disallow asset locking inside the `Channel`.
    public fun create_channel<T: store + drop>(t: T, ctx: &mut TxContext): Channel<T> {
        Channel {
            id: object::new(ctx),
            messages: vec_set::empty(),
            data: t
        }
    }

    /// Spawn a message from the passed data and signatures. Data is processed and
    /// used to construct a `Message` struct, and the signatures are checked to be
    /// of current validators from the validator set.
    public fun create_message(
        v: &Validators,

        data: vector<u8>,
        operators: vector<address>,
        weights: vector<u64>,
        threshold: u64,
        signatures: vector<vector<u8>>,

        ctx: &mut TxContext
    ): Message {
        assert!(validate_proof(
            v,
            crypto::keccak256(data),
            operators,
            weights,
            threshold,
            signatures
        ), ESignatureInvalid);

        // TODO: set on the message bytes format to make data parse-able
        let ( source, destination, target_id, payload ) = parse_message(data);

        Message {
            id: object::new(ctx),
            target_id,
            source,
            destination,
            payload,
        }
    }

    /// By using &mut here we make sure that the object is not in the freeze
    /// state and the owner has edit access to the target.
    ///
    /// Most common scenario would be to target a shared object, however this
    /// messaging system allows sending private messages which can be consumed
    /// by single-owner targets.
    ///
    /// TODO: consider returning a droppable object instead of tuple.
    public fun consume_message<T: store + drop>(t: &mut Channel<T>, m: Message): (vector<u8>, vector<u8>, vector<u8>) {
        let Message { id, target_id, source, destination, payload } = m;

        // TODO: figure out a way to provide unique identifier for the message (payload? signatures? hash contents?)
        assert!(!vec_set::contains(&t.messages, &sha3_256(payload)), EDuplicateMessage);
        assert!(target_id == object::id_bytes(t), EWrongDestination);
        object::delete(id);

        (source, destination, payload)
    }

    /// Send a message to another chain. Supply the event data and the
    /// destination chain.
    public fun send_message<T: store + drop>(
        t: &mut Channel<T>,
        destination: vector<u8>,
        destination_address: vector<u8>,
        payload: vector<u8>
    ) {
        // TODO: think what else is required here ;

        sui::event::emit(MessageSent {
            source: object::id_bytes(t),
            destination,
            destination_address,
            payload,
        })
    }

    /// Internal function which parses message bytes and returns message parameters:
    /// ( source_chain, destination_chain, destination_address, payload )
    ///
    /// Consider using BCS bytes for that...
    fun parse_message(_msg: vector<u8>): (vector<u8>, vector<u8>, vector<u8>, vector<u8>) {
        (
            vector[],
            vector[],
            vector[],
            vector[]
        )
    }

    /// Implementation of the `AxelarAuthWeighted.validateProof`.
    /// Does proof validation, fails when proof is invalid or if weight
    /// threshold is not reached.
    fun validate_proof(
        validators: &Validators,

        hash: vector<u8>,
        operators: vector<address>,
        weights: vector<u64>,
        threshold: u64,
        signatures: vector<vector<u8>>
    ): bool {
        // turn everything into bcs bytes and merge together
        let operators_hash = crypto::keccak256(bcs::to_bytes(&vector[
            bcs::to_bytes(&operators),
            bcs::to_bytes(&weights),
            bcs::to_bytes(&threshold),
        ]));

        let operators_length = vec::length(&operators);
        let operators_epoch = *vec_map::get(&validators.epoch_for_hash, &operators_hash);
        let epoch = validators.epoch;

        assert!(operators_epoch != 0 && epoch - operators_epoch < OLD_KEY_RETENTION, 0); // EInvalidOperators

        // _validateSignatures() implementation
        let (i, weight, operator_index) = (0, 0, 0);
        let total_signatures = vec::length(&signatures);

        while (i < total_signatures) {
            let signed_by = crypto::ecrecover(*vec::borrow(&signatures, i), *&hash);
            while (operator_index < operators_length && &signed_by != &bcs::to_bytes(vec::borrow(&operators, operator_index))) {
                operator_index = operator_index + 1;
            };

            assert!(operator_index == operators_length, 0); // EMalformedSigners

            weight = weight + *vec::borrow(&weights, operator_index);
            if (weight >= threshold) { return true };
            operator_index = operator_index + 1;
        };

        abort 0 // ELowSignaturesWeight
    }
}
