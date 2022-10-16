// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * This package generates test data for the Axelar
 * General Message Passing protocol
 */

const { ethers, utils: { keccak256 } } = require('ethers');
const { bcs, fromHEX } = require('@mysten/bcs');

// to generate new MNEMONIC and ADDRESS use:
// const wallet = ethers.Wallet.createRandom();
// const MNEMONIC = wallet.mnemonic;

const MNEMONIC = 'under elbow cherry basic stuff salad position gym harbor soup enough dignity';
const ADDRESS  = '0xe46c640828a7e9277c0035d90332edf9ed18bf93';

const wallet = ethers.Wallet.fromMnemonic(MNEMONIC);

// input argument for the tx
bcs.registerStructType('Input', {
    data: 'vector<u8>',
    proof: 'vector<u8>'
});

// internals of the message
bcs.registerStructType('AxelarMessage', {
    chain_id: 'u64',
    command_ids: 'vector<string>',
    commands: 'vector<string>',
    params: 'vector<vector<u8>>'
});

// defines channel target
bcs.registerStructType('GenericMessage', {
    source_chain: 'string',
    source_address: 'string',
    target_id: 'SuiAddress',
    payload_hash: 'vector<u8>',

    payload: 'vector<u8>',
});

// basic and utility types
bcs.registerVectorType('vector<u8>', 'u8');
bcs.registerVectorType('vector<vector<u8>>', 'vector<u8>');
bcs.registerVectorType('vector<string>', bcs.STRING);
bcs.registerAddressType('SuiAddress', 20, 'hex');

const message = bcs.ser('AxelarMessage', {
    chain_id: '1',
    command_ids: [ 'rogue_one', 'axelar_two' ],
    commands: [
        'do_something_fun',
        'do_it_again',
    ],
    params: [
        bcs.ser('GenericMessage', {
            source_chain: 'ETH',
            source_address: '0x0',
            payload_hash: [0,0,0,0],
            target_id: ADDRESS, // using address here for simlicity...
            payload: [0,0,0,0,0]
        }).toBytes(),
        bcs.ser('GenericMessage', {
            source_chain: 'AXELAR',
            source_address: '0x1',
            payload_hash: [0,0,0,0],
            target_id: ADDRESS, // ...
            payload: [0,0,0,0,0]
        }).toBytes(),
    ]
}).toBytes();

const message_hash = keccak256(message);
const input = bcs.ser('Input', {
    proof: [ 1, 2, 3, 4, 5, 6 ],
    data: message
});

console.log(input.toString('hex'));

