pragma circom 2.1.6;

include "./crypto/rsa_check.circom";
include "./jwt/claim_inclusion.circom";
include "./utils/concat.circom";
include "./utils/checknonce.circom";
include "./zk-email/circuits/lib/circomlib/circuits/poseidon.circom";


template ZKLogin(
  nonce_claim_bytes,
  phone_claim_bytes,
  nonce_bytes,
  phone_bytes,
  jwt_chunk_size,
  chunk_count,
  n, k
){  
    // input signals
    signal input jwt_segments[chunk_count][jwt_chunk_size]; // split jwt into chunk_count chunks of jwt_chunk_size
    signal input jwt_sha256[256];
    signal input nonce[nonce_claim_bytes];//Nonce
    signal input phone[phone_claim_bytes]; // phone number
    signal input phone_loc;
    signal input nonce_loc;
    signal input signature[k];
    signal input modulus[k];

    signal input highpartPK; // public input
    signal input lowpartPK; // public input
    signal input exp; // public input
    signal input project_id; // public input

    // output signals
    signal output phone_out_ascii_hash;

    // 1. verify the signature
    component rsa_sha256 = Rsa_check(n, k);
    rsa_sha256.jwt_sha256 <== jwt_sha256;
    rsa_sha256.modulus <== modulus;
    rsa_sha256.signature <== signature;

    // 2. prove claims inclusions

    //-------------------------------------------
    // 2.1 nonce_out has "nonce_bytes" ascii numbers 
    signal nonce_out[nonce_bytes] <== ClaimInclusion(nonce_claim_bytes, nonce_bytes, jwt_chunk_size, chunk_count)(jwt_segments, nonce, nonce_loc);

    // verify nonce=H(addr, exp, project_id)
    //1) Since it is impossible to determine whether the length of the nonce text is 76 or 77, only the first 76 character of the nonce text are taken for comparison, and then 10 77-digit numbers are obtained through algebraic operations for comparison.
    //2) Since it is impossible to determine whether there are colon or quotes in the first two characters, the nonce can be divided into the following three situations:
    // :"nonce            There are two useless characters in front of the text of nonce
    // :nonce, "nonce     There is a useless character in front of the text of nonce
    // nonce              There are no useless characters in front of the nonce text.
    component hash = Poseidon(4);
    hash.inputs[0] <== highpartPK;
    hash.inputs[1] <== lowpartPK;
    hash.inputs[2] <== exp;
    hash.inputs[3] <== project_id;

    component checknonce[3];
    checknonce[0] = Ascii2Num_CheckNonce();
    checknonce[0].hash <== hash.out;
    for (var j = 0; j < 76; j++) {
        checknonce[0].nonce[j] <== nonce_out[j+2];
    }
    checknonce[1] = Ascii2Num_CheckNonce();
    checknonce[1].hash <== hash.out;
    for (var j = 0; j < 76; j++) {
        checknonce[1].nonce[j] <== nonce_out[j+1];
    }
    checknonce[2] = Ascii2Num_CheckNonce();
    checknonce[2].hash <== hash.out;
    for (var j = 0; j < 76; j++) {
        checknonce[2].nonce[j] <== nonce_out[j];
    }
    checknonce[0].out + checknonce[1].out + checknonce[2].out === 1;


    //-------------------------------------------
    // 2.2 phone claims inclusions
    signal phone_ascii[phone_bytes] <== ClaimInclusion(
      phone_claim_bytes, phone_bytes, jwt_chunk_size, chunk_count
    )(jwt_segments, phone, phone_loc);

    signal move_temp_phone[17];
    signal phone_num[16];
    signal isColon_phone_0 <== IsEqual()([phone_ascii[0],58]); //1 means equal, 0 means unequal
    signal isColon_phone_1 <== IsEqual()([phone_ascii[1],58]); //1 means equal, 0 means unequal
    signal isQuote_phone_0 <== IsEqual()([phone_ascii[0],34]); //1 means equal, 0 means unequal
    signal isQuote_phone_1 <== IsEqual()([phone_ascii[1],34]); //1 means equal, 0 means unequal

    component mux1_phone[17];
    component mux2_phone[16];
    for(var i = 0; i < 17; i++ ){
        mux1_phone[i] = Mux1(); 
        mux1_phone[i].c[0] <== phone_ascii[i];
        mux1_phone[i].c[1] <== phone_ascii[i+1];
        mux1_phone[i].s <== isColon_phone_0 + isQuote_phone_0; 
        move_temp_phone[i] <== mux1_phone[i].out;
    }
    for(var i = 0; i < 16; i++ ){
        mux2_phone[i] = Mux1(); 
        mux2_phone[i].c[0] <== move_temp_phone[i];
        mux2_phone[i].c[1] <== move_temp_phone[i+1];
        mux2_phone[i].s <== isColon_phone_1 + isQuote_phone_1; 
        phone_num[i] <== mux2_phone[i].out;
    }

    component clear_Quote_Comma[16];
    signal clear_Quote[16];
    signal clear_Comma[16];
    signal clear_phone_num[16];

    for(var i = 0; i < 16; i++ ){
        clear_Comma[i] <== IsEqual()([phone_num[i],44]);
        clear_Quote[i] <== IsEqual()([phone_num[i],34]);
        clear_Quote_Comma[i] = Mux1(); 
        clear_Quote_Comma[i].c[0] <== phone_num[i];
        clear_Quote_Comma[i].c[1] <== 0;
        clear_Quote_Comma[i].s <== clear_Comma[i]+clear_Quote[i];
        clear_phone_num[i] <== clear_Quote_Comma[i].out;
    }

    signal phone_out_ascii <== ConcatDigits(2, 16)(clear_phone_num);

    component phone_hash = Poseidon(1);
    phone_hash.inputs[0] <== phone_out_ascii;
    phone_out_ascii_hash <== phone_hash.out;
}


component main{ public [project_id, highpartPK, lowpartPK, exp]} = ZKLogin(108, 24, 79, 18, 16, 64, 121, 17);
