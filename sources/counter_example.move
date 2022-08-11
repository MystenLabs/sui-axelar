// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module axelar::counter {
    use sui::transfer;
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};

    /// A shared counter.
    struct Counter has key {
        id: UID,
        owner: address,
        value: u64
    }

    public fun owner(counter: &Counter): address { counter.owner }
    public fun value(counter: &Counter): u64 { counter.value }

    /// Create and share a Counter object.
    public entry fun create(ctx: &mut TxContext) {
        transfer::share_object(Counter {
            id: object::new(ctx),
            owner: tx_context::sender(ctx),
            value: 0
        })
    }

    /// Increment a counter by 1.
    public entry fun increment(counter: &mut Counter) {
        counter.value = counter.value + 1;
    }

    /// Assert a value for the counter.
    public entry fun assert_value(counter: &Counter, value: u64) {
        assert!(counter.value == value, 0)
    }
}

/// Example implementation of a messenger service for the
module axelar::counter_axelar_interface {
    use axelar::messenger::{Self, Channel, Validators as AxelarValidators};
    use axelar::counter::{Self, Counter};
    use sui::tx_context::{TxContext};
    use sui::object::{Self, ID};

    /// For when `Channel` is targeting a wrong `Counter`
    const ETargetMismatch: u64 = 0;

    /// Create a `Channel` object pointing to a `Counter`. Any `Counter` can be used for that
    /// and there's no limit to how many objects there are.
    public fun setup_interface(for: &Counter, ctx: &mut TxContext): Channel<ID> {
        messenger::create_channel(object::id(for), ctx)
    }

    /// Do the magic of message processing using the `messenger` module.
    /// The only problem here is the amount of shared objects required to make it go through.
    ///
    /// Relaxing the data linking and allowing message creation without its invocation might
    /// lead to command never getting executed. Alternatively, we could store messages in a
    /// Channel but that opens up a whole lot of security vulnerabilities related to delays.
    public entry fun process_msg(
        validators: &AxelarValidators,
        channel: &mut Channel<ID>,
        counter: &mut Counter,

        msg_data: vector<u8>,
        signatures: vector<vector<u8>>,
    ) {
        // if this passes, we're good
        let message = messenger::create_message(validators, msg_data, signatures);
        let ( _source, _destination, payload ) = messenger::consume_message(channel, message);

        assert!(messenger::channel_data(channel) == &object::id(counter), ETargetMismatch);

        if (payload == b"increment") {
            counter::increment(counter);
        }
    }
}
