pragma circom 2.1.6;

include "../zk-email/circuits/lib/circomlib/circuits/bitify.circom";
include "../zk-email/circuits/lib/rsa.circom";

template Rsa_check(n, k) {
  signal input jwt_sha256[256];
  signal input modulus[k];
  signal input signature[k];

  signal output out[n];

  var msg_len = (256 + n) \ n;

  component base_msg[msg_len];
  for (var i = 0; i < msg_len; i++) {
    base_msg[i] = Bits2Num(n);
  }

  for (var i = 0; i < 256; i++) {
    base_msg[i \ n].in[i % n] <== jwt_sha256[255 - i];
  }

  for (var i = 256; i < n * msg_len; i++) {
    base_msg[i \ n].in[i % n] <== 0;
  }

  component rsa = RSAVerifier65537(n, k);
  for (var i = 0; i < msg_len; i++) {
    rsa.message[i] <== base_msg[i].out;
  }
  
  for (var i = msg_len; i < k; i++) {
    rsa.message[i] <== 0;
  }

  for (var i = 0; i < k; i++) {
    rsa.modulus[i] <== modulus[i];
    rsa.signature[i] <== signature[i];
  }
}
