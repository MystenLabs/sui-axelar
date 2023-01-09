// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * This package generates test data for the Axelar
 * General Message Passing protocol
 */

const secp256k1 = require("secp256k1");
const {
  utils: { keccak256 },
} = require("ethers");
const { BCS, fromHEX, toHEX, getSuiMoveConfig } = require("@mysten/bcs");
const bcs = new BCS(getSuiMoveConfig());

// generate privKey
const privKey = Buffer.from(
  "9027dcb35b21318572bda38641b394eb33896aa81878a4f0e7066b119a9ea000",
  "hex"
);

// get the public key in a compressed format
const pubKey = secp256k1.publicKeyCreate(privKey);

// input argument for the tx
bcs.registerStructType("Input", {
  data: "vector<u8>",
  proof: "vector<u8>",
});

bcs.registerStructType("Proof", {
  // operators is a 33 byte / for now at least
  operators: "vector<vector<u8>>",
  weights: "vector<u64>",
  threshold: "u64",
  signatures: "vector<vector<u8>>",
});

// internals of the message
bcs.registerStructType("AxelarMessage", {
  chain_id: "u64",
  command_ids: "vector<string>",
  commands: "vector<string>",
  params: "vector<vector<u8>>",
});

// defines channel target
bcs.registerStructType("GenericMessage", {
  source_chain: "string",
  source_address: "string",
  target_id: "address",
  payload_hash: "vector<u8>",

  payload: "vector<u8>",
});

const ZERO_ADDR = "0x".padEnd(62, "0");
const message = bcs
  .ser("AxelarMessage", {
    chain_id: 1,
    command_ids: ["rogue_one", "axelar_two"],
    commands: ["approveContractCall", "approveContractCall"],
    params: [
      bcs
        .ser("GenericMessage", {
          source_chain: "ETH",
          source_address: "0x0",
          payload_hash: [0, 0, 0, 0],
          target_id: ZERO_ADDR, // using address here for simlicity...
          payload: [0, 0, 0, 0, 0],
        })
        .toBytes(),
      bcs
        .ser("GenericMessage", {
          source_chain: "AXELAR",
          source_address: "0x1",
          payload_hash: [0, 0, 0, 0],
          target_id: ZERO_ADDR, // ...
          payload: [0, 0, 0, 0, 0],
        })
        .toBytes(),
    ],
  })
  .toBytes();

const hashed = fromHEX(hashMessage(message));
const { signature, recid } = secp256k1.ecdsaSign(hashed, privKey);

const proof = bcs
  .ser("Proof", {
    operators: [pubKey],
    weights: [100],
    threshold: 10,
    signatures: [new Uint8Array([...signature, recid])],
  })
  .toBytes();

const input = bcs
  .ser("Input", {
    data: message,
    proof: proof,
  })
  .toString("hex");

console.log("OPERATOR: %s", toHEX(pubKey));
console.log("DATA LENGTH: %d", message.length);
console.log("PROOF LENGTH: %d", proof.length);
console.log("INPUT: %s", input + "00");

// verify the signature // just to make sure that everything is correct on this end
console.log(secp256k1.ecdsaVerify(signed_data, hashed, pubKey));

{
  const testData = fromHEX(hashMessage("hello world bee"));
  const { recid, signature } = secp256k1.ecdsaSign(testData, privKey);

  // don't forget to add '00' to the end of the signature
  console.log("message", hashMessage("hello world").replace("0x", ""));
  console.log("signature", toHEX(signature) + recid.toString(16).padStart(2, 0));
  console.log(secp256k1.ecdsaVerify(signature, testData, pubKey));
  // console.log(secp256k1.ecdsaRecover(signature, recid, testData));
}

/**
 * Add a prefix to a message.
 * Return resulting array of bytes.
 */
function hashMessage(data) {
  // sorry for putting it here...
  const messagePrefix = new Uint8Array(
    Buffer.from("\x19Sui Signed Message:\n", "ascii")
  );
  let hashed = new Uint8Array(messagePrefix.length + data.length);
  hashed.set(messagePrefix);
  hashed.set(data, messagePrefix.length);

  return keccak256(hashed);
}
