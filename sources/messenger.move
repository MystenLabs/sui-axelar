// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Implementation a cross-chain messaging system for Axelar.
///
/// This code is based on the following:
///
/// - When message is sent to Sui, it targets an object and not a module;
/// - To support cross-chain messaging, a Beacon object has to be created;
/// - Beacon can be either owned or shared but not frozen;
/// - Module developer on the Sui side will have to implement a system to support messaging;
/// - Checks for uniqueness of messages should be done through `Beacon`s to avoid big data storage;
///
/// I. Sending messages
///
/// A message is sent through the `send` function, a Beacon is supplied to determine the source -> ID.
/// Event is then emitted and Axelar network can operate
///
/// II. Receiving messages
///
/// Message bytes and signatures are passed into `create` function to generate a Message object.
///  - Signatures are checked against the known set of validators.
///  - Message bytes are parsed to determine: source, destination_chain, payload and target_id
///  - `target_id` points to a `Beacon` object
///
/// Once created, `Message` needs to be consumed. And the only way to do it is by calling `consume`
/// function and pass a correct `Beacon` instance alongside the `Message`.
///  - Message is checked for uniqueness (for this beacon)
///  - Message is checked to match the `Beacon`.id
///
module me::messenger {
    use sui::object::{Self, UID};
    use sui::vec_set::{Self, VecSet};
    use std::vector as vec;
    use std::hash::sha3_256;

    const SUI_SOURCE: vector<u8> = b"SUI";

    /// For when trying to consume the wrong object.
    const EWrongDestination: u64 = 0;

    /// For when message signatures failed verification.
    const ESignatureInvalid: u64 = 1;

    /// For when message has already been processed and submitted twice.
    const EDuplicateMessage: u64 = 2;

    /// Generic target for the messaging system.
    ///
    /// This object is required on the Sui side to be the destination for the
    /// messages sent from other chains.
    struct Beacon<T: store> has key, store {
        /// Unique ID of the target object which allows message targeting
        /// by comparing against `id_bytes`.
        id: UID,
        /// Messages processed by this object. To make system less
        /// centralized, and spread the storage + io costs accross multiple
        /// destinations, we can track every `Beacon`'s messages.
        messages: VecSet<vector<u8>>,
        /// Additional field to optionally use as metadata for the Beacon
        /// object improving identification and uniqueness of data.
        /// Can store any struct that has `store` ability.
        data: T
    }

    /// Message 'Hot Potato' which can only be consumed if a `Beacon` object
    /// is supplied. Does not require additional generic field to operate
    /// as linking by `id_bytes` is more than enough.
    struct Message {
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

    /// Spawn a message from the passed data and signatures. Data is processed and
    /// used to construct a `Message` struct, and the signatures are checked to be
    /// of current validators from the validator set.
    public fun create(/* &mut Validators */ data: vector<u8>, signatures: vector<vector<u8>>): Message {
        assert!(validate_signatures(signatures), ESignatureInvalid);

        // TODO: set on the message bytes format to make data parse-able
        let ( source, destination, target_id, payload ) = parse_message(data);

        Message {
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
    public fun consume<T: store>(t: &mut Beacon<T>, m: Message): (vector<u8>, vector<u8>, vector<u8>) {
        let Message { target_id, source, destination, payload } = m;

        // TODO: figure out a way to provide unique identifier for the message (payload? signatures? hash contents?)
        assert!(!vec_set::contains(&t.messages, &sha3_256(payload)), EDuplicateMessage);
        assert!(target_id == object::id_bytes(t), EWrongDestination);

        (source, destination, payload)
    }

    /// Send a message to another chain. Supply the event data and the
    /// destination chain.
    public fun send<T: store>(
        t: &mut Beacon<T>,
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
    fun parse_message(_msg: vector<u8>): (vector<u8>, vector<u8>, vector<u8>, vector<u8>) {
        (
            vec::empty(),
            vec::empty(),
            vec::empty(),
            vec::empty()
        )
    }

    /// Mocked version of the signature verification function.
    /// Requires a shared object with the list of validators to make sure the signatures match
    fun validate_signatures(/* &mut Validators, */ _signatures: vector<vector<u8>>): bool {
        true
    }
}

// We'll need something like that for the signature recovery
module me::crypto {
    public fun ecdsa_recover(_msg: vector<u8>, _signatures: vector<vector<u8>>): vector<address> {
        use std::vector as vec;

        let v = vec::empty();
        vec::push_back(&mut v, @0x1);
        vec::push_back(&mut v, @0x2);
        vec::push_back(&mut v, @0x3);
        vec::push_back(&mut v, @0x4);
        v
    }
}
