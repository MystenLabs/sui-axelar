// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * This package generates test data for the Axelar
 * General Message Passing protocol
 */

const secp256k1 = require('secp256k1')
const { utils: { keccak256 } } = require('ethers');
const { bcs, fromHEX, toHEX } = require('@mysten/bcs');

// generate privKey
const privKey = Buffer.from('9027dcb35b21318572bda38641b394eb33896aa81878a4f0e7066b119a9ea000', 'hex');

// get the public key in a compressed format
const pubKey = secp256k1.publicKeyCreate(privKey);

// input argument for the tx
bcs.registerStructType('Input', {
    data: 'vector<u8>',
    proof: 'vector<u8>'
});

bcs.registerStructType('Proof', {
    // operators is a 33 byte / for now at least
    operators: 'vector<vector<u8>>',
    weights: 'vector<u64>',
    threshold: 'u64',
    signatures: 'vector<vector<u8>>'
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
bcs.registerVectorType('vector<u64>', 'u64');
bcs.registerVectorType('vector<vector<u8>>', 'vector<u8>');
bcs.registerVectorType('vector<SuiAddress>', 'SuiAddress');
bcs.registerVectorType('vector<string>', bcs.STRING);
bcs.registerAddressType('SuiAddress', 20, 'hex');

const ZERO_ADDR = '0x'.padEnd(62, '0');
const message = bcs.ser('AxelarMessage', {
    chain_id: 1,
    command_ids: [ 'rogue_one', 'axelar_two' ],
    commands: [
        'approveContractCall',
        'approveContractCall',
    ],
    params: [
        bcs.ser('GenericMessage', {
            source_chain: 'ETH',
            source_address: '0x0',
            payload_hash: [0,0,0,0],
            target_id: ZERO_ADDR, // using address here for simlicity...
            payload: [0,0,0,0,0]
        }).toBytes(),
        bcs.ser('GenericMessage', {
            source_chain: 'AXELAR',
            source_address: '0x1',
            payload_hash: [0,0,0,0],
            target_id: ZERO_ADDR, // ...
            payload: [0,0,0,0,0]
        }).toBytes(),
    ]
}).toBytes();

const hashed = fromHEX(keccak256(message));
const signed_data = secp256k1.ecdsaSign(hashed, privKey).signature;

const proof = bcs.ser('Proof', {
    operators: [ pubKey ],
    weights: [ 100 ],
    threshold: 10,
    signatures: [ new Uint8Array([...signed_data, 0]) ]
}).toBytes();

const input = bcs.ser('Input', {
    data: message,
    proof: proof
}).toString('hex');

console.log('OPERATOR: %s', toHEX(pubKey));
console.log('DATA LENGTH: %d', message.length);
console.log('PROOF LENGTH: %d', proof.length);
console.log('INPUT: %s', input)

// console.log('VALIDATOR PUB_KEY: %s', toHEX(pubKey));
// console.log('MESSAGE: %s', toHEX(message));
// console.log('HASHED MESSAGE: %s', toHEX(hashed));
// console.log('SIGNATURE: %s', toHEX(signed_data) + '00');

// verify the signature
// console.log(secp256k1.ecdsaVerify(sigObj.signature, hashed, pubKey))
