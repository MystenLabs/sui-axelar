// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module axelar::coin_bridge {
    use sui::coin::{Self, Coin, TreasuryCap};
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};
    use sui::transfer;

    use axelar::messenger::{Self, Validators as AxelarValidators, Beacon};

    /// For when Bridge currency mismatches expected one.
    const EWrongSymbol: u64 = 0;

    /// Bridge object which controls minting
    struct Bridge<phantom T> has key {
        id: UID,
        symbol: vector<u8>,
        beacon: Beacon<bool>, // meh, just putting bool there
        treasury_cap: TreasuryCap<T>
    }

    /// ... can be called by anyone if they provide enough signatures
    public fun create_bridge<T: drop>(w: T, symbol: vector<u8>, ctx: &mut TxContext) {
        transfer::share_object(Bridge {
            id: object::new(ctx),
            symbol,
            treasury_cap: coin::create_currency(w, ctx),
            beacon: messenger::create_beacon(true, ctx),
        })
    }

    /// Mint a token on the Sui side by supplying correct information from the outside.
    /// The message has to target Bridge's Beacon, hence there is only one possible target
    /// for the Bridge.
    public entry fun mint<T>(
        validators: &AxelarValidators,
        bridge: &mut Bridge<T>,

        msg_data: vector<u8>,
        signatures: vector<vector<u8>>,

        ctx: &mut TxContext
    ) {
        let message = messenger::create_message(validators, msg_data, signatures);
        let ( _source, _destination, payload ) = messenger::consume_message(&mut bridge.beacon, message);
        let (receiver, symbol, amount) = parse_msg_payload(payload);

        assert!(bridge.symbol == symbol, EWrongSymbol);

        transfer::transfer(
            coin::mint(&mut bridge.treasury_cap, amount, ctx),
            receiver
        )
    }

    /// Transfer Coin by burning it and emitting a messenger event.
    /// Supply additional parameters for the
    public entry fun burn<T>(
        bridge: &mut Bridge<T>,
        coin: Coin<T>,

        destination: vector<u8>,
        destination_address: vector<u8>,
        target_address: vector<u8>,

        ctx: &mut TxContext
    ) {
        // TODO: figure out how to construct payload based on:
        // ( amount, sender, target_address )
        let payload = construct_payload(
            coin::burn(&mut bridge.treasury_cap, coin),
            tx_context::sender(ctx),
            target_address
        );

        messenger::send_message(
            &mut bridge.beacon,
            destination,
            destination_address,
            payload
        );
    }

    fun parse_msg_payload(_p: vector<u8>): (address, vector<u8>, u64) {
        (@0x2, b"ETH", 10000)
    }

    fun construct_payload(
        _amount: u64, _sender: address, _target: vector<u8>
    ): vector<u8> {
        vector[]
    }
}
