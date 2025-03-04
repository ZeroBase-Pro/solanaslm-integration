Example code to generate Ed25519 key pair

    const nacl = require('tweetnacl');
    const keyPair = nacl.sign.keyPair();
    const publicKey = keyPair.publicKey;
    const highPart = publicKey.slice(0, 16);
    const lowPart = publicKey.slice(16);
    const highBigInt = BigInt('0x' + Buffer.from(highPart).toString('hex'));
    const lowBigInt = BigInt('0x' + Buffer.from(lowPart).toString('hex'));
    console.log(keyPair.secretKey);
    console.log(keyPair.publicKey);
    console.log(highBigInt);
    console.log(lowBigInt);


private key + public key:
[1] Uint8Array(64) [ 207, 200, 14, 222, 178, 22, 50, 201, 254, 89, 183, 25, 77, 151, 162, 54, 67, 168, 185, 255, 153, 56, 190, 200, 32, 166, 210, 1, 170, 98, 68, 205, 143, 58, 68, 96, 251, 76, 194, 89, 41, 101, 205, 226, 134, 240, 135, 116, 202, 77, 169, 9, 161, 126, 157, 19, 230, 44, 217, 11, 186, 56, 122, 61 ]

public key:
[1] Uint8Array(32) [ 143, 58, 68, 96, 251, 76, 194, 89, 41, 101, 205, 226, 134, 240, 135, 116, 202, 77, 169, 9, 161, 126, 157, 19, 230, 44, 217, 11, 186, 56, 122, 61 ]

We split the public key into high part and low part:

In this example
highBigInt: 190382143502568173121953655840023021428
lowBigInt: 268907290496916820827766377268916025917