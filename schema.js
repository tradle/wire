/**
 * flow:
 *
 * A                    B
 *      --> open
 *      <-- handshake
 *      --> handshake
 *      <--> data/ack
 */
module.exports = require('protocol-buffers')(`
  // ack = seq of last message received

  message Handshake {
    required bytes ephemeralKey = 1;
    required bytes staticKey = 2;
    // whether the sender has already authenticated
    // the receiver. If false, the receiver should send its own handshake
    required bool authenticated = 3;
  }

  message Encrypted {
    required bytes ephemeralKey = 1;
    required uint32 counter = 2;
    required uint32 previousCounter = 3;
    required bytes ciphertext = 4;
    required bytes nonce = 5;
  }

  // Encrypted messages ciphertext contain one of the following:
  message Request {
    required uint32 seq = 1;
  }

  message Data {
    required bytes payload = 1;
    required uint32 ack = 2;
  }

  message Ack {
    required uint32 ack = 1;
  }
`)
