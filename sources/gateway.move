// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Attempt to write a Gateway module.
///
/// Based on few assumptions:
/// - there's one "admin" account which does admin actions;
/// - one Gateway serves one token; for simplicity's sake no limitations are set;
/// - the only way to get destination information is by scanning txs / events;
///
module me::gateway {
    use sui::object::{Self, ID, UID};
    use sui::transfer;
    use sui::event;
    use sui::coin::{Self, Coin, TreasuryCap};
    use sui::tx_context::{Self, TxContext};

    /// The Capability to interact with the gate. Only issued once.
    struct GatekeeperCapability has key {
        id: UID
    }

    /// The Gateway itself. One per each Coin<T>.
    struct Gateway<phantom T> has key {
        id: UID,
        treasury: TreasuryCap<T>,
    }

    // ====== Events ======

    /// Event. Emitted when a new Gateway is created.
    struct TokenDeployed<phantom T> has copy, drop {
        id: ID
    }

    /// Event. Emitted when someone transfers their tokens to
    /// another network.
    struct TokenSent<phantom T> has copy, drop {
        gateway: ID,
        sender: address,
        destination_chain: vector<u8>,
        destination_address: vector<u8>,
        symbol: vector<u8>,
        amount: u64
    }

    /// Event. Emitted when admin mints some `amount` of Coin<T>
    /// for the `receiver` at `Gateway`.
    struct TokenMinted<phantom T> has copy, drop {
        gateway: ID,
        receiver: address,
        amount: u64,
    }

    /// Module initializer. Create one GatekeeperCapability and
    /// send it to sender.
    fun init(ctx: &mut TxContext) {
        transfer::transfer(GatekeeperCapability {
            id: object::new(ctx),
        }, tx_context::sender(ctx))
    }

    // ====== Admin functions =====

    /// Create a shared object Gateway<T> which will be used to mint/burn T.
    /// Requires a module type with drop (see `eth_gate`), also requires
    /// GatekeeperCapability which only module creator owns.
    public fun deploy_gate<T: drop>(witness: T, _: &GatekeeperCapability, ctx: &mut TxContext) {
        // id of the deployed gateway
        let id = object::new(ctx);

        // emit event before variable got moved
        event::emit(TokenDeployed<T> { id: *object::uid_as_inner(&id) });
        transfer::share_object(Gateway {
            id,
            treasury: coin::create_currency(witness, ctx)
        })
    }

    // tx gateway::mint_token gatewayId, capId, amount

    /// Admin action of minting and sending coin to the receiver on Sui side.
    /// Only callable for existing Gateway<T> by owner of the GatekeeperCapability.
    public fun mint_token<T>(
        gate: &mut Gateway<T>,
        _: &GatekeeperCapability,
        amount: u64,
        receiver: address,
        ctx: &mut TxContext
    ) {
        event::emit(TokenMinted<T> {
            gateway: object::id(gate),
            amount,
            receiver
        });

        transfer::transfer(coin::mint(&mut gate.treasury, amount, ctx), receiver)
    }

    // Sol: 'ETH' -> Sui: '0x0.....::eth_gate::ETH'

    // ====== Public accessors =====

    /// Send token from Sui somewhere else, callable by anyone.
    /// Tokens of type T can only be passed through their Gateway<T>.
    ///
    /// Burn happens instantly and a TokenSent event emitted.
    public entry fun send_token<T>(
        gate: &mut Gateway<T>,
        coin: Coin<T>,
        destination_chain: vector<u8>,
        destination_address: vector<u8>,
        symbol: vector<u8>,
        ctx: &mut TxContext
    ) {
        event::emit(TokenSent<T> {
            sender: tx_context::sender(ctx),
            gateway: object::id(gate),
            destination_chain,
            destination_address,
            symbol,
            amount: coin::value(&coin)
        });

        coin::burn(&mut gate.treasury, coin);
    }

    #[test_only]
    /// Only callable in tests to emulate module initializer.
    public fun init_for_testing(ctx: &mut TxContext) {
        init(ctx)
    }
}

/// An example of a deployed gateway contract.
/// Calls `gateway::deploy_gate` with a witness type published in
/// this module making it impossible to fake type signature.
///
/// Since `deploy_gate` also requires `GatekeeperCapability`,
/// the action can be performed only by admin account.
module me::eth_gate {
    use sui::transfer;
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use me::gateway::{Self, GatekeeperCapability};

    /// A one-time Capability given to the module publisher
    /// in module initializer. Contains a witness which is
    /// then used to deploy a new Gateway.
    struct DeployCapability has key {
        id: UID,
        witness: ETH
    }

    /// The type to use as a witness later. Has store
    /// to be put into a one-time DeployCapability.
    struct ETH has store, drop {}

    /// Module initializer. Called once on module publish.
    /// Sends a `DeployCapability` to the sender
    fun init(ctx: &mut TxContext) {
        transfer::transfer(DeployCapability {
            id: object::new(ctx),
            witness: ETH {}
        }, tx_context::sender(ctx))
    }

    /// Deploy a new Gateway.
    ///
    /// - Consumes `DeployCapability` taking a `witness`.
    /// - Requires `GatekeeperCapability` to authorize action.
    /// - Can only be called once.
    public entry fun deploy(
        deploy_cap: DeployCapability,
        gate_cap: &GatekeeperCapability,
        ctx: &mut TxContext
    ) {
        let DeployCapability { id, witness } = deploy_cap;
        object::delete(id);

        gateway::deploy_gate(witness, gate_cap, ctx)
    }

    #[test_only]
    /// Test-only module initializer.
    public fun init_for_testing(ctx: &mut TxContext) {
        init(ctx)
    }
}

#[test_only]
module me::test_gateway {
    use sui::test_scenario::{Self as test, next_tx, ctx};
    use me::gateway::{Self, GatekeeperCapability};
    use me::eth_gate::{Self, DeployCapability};

    #[test]
    fun test_deploy_gate() {
        let (admin, _) = people();
        let test = &mut test::begin(&admin);

        // Init the gateway module, get the admin capability;
        next_tx(test, &admin); {
            gateway::init_for_testing(ctx(test));
        };

        // Init the eth_gate module;
        next_tx(test, &admin); {
            eth_gate::init_for_testing(ctx(test));
        };

        // Deploy, use the one-timer and a GatekeeperCap.
        // Take both from the inventory and put back once used.
        next_tx(test, &admin); {
            let gatekeeper_cap = test::take_owned<GatekeeperCapability>(test);
            let deploy_cap = test::take_owned<DeployCapability>(test);

            eth_gate::deploy(deploy_cap, &gatekeeper_cap, ctx(test));

            test::return_owned(test, gatekeeper_cap);
        };
    }

    // Handy getter for account play.
    fun people(): (address, address) { (@0xFEE, @0xF00) }
}
