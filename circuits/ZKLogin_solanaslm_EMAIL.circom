pragma circom 2.1.6;

include "./crypto/rsa_check.circom";
include "./jwt/claim_inclusion.circom";
include "./utils/concat.circom";
include "./utils/checknonce.circom";
include "./zk-email/circuits/lib/circomlib/circuits/poseidon.circom";


/// 1. This circuit verifies the JWT signature (RSA256) by given modulus.
/// 2. Ensure the encoded `nonce` is included in the JWT token, verify the correctness of nonce.
/// 3. Base64 decode the `nonce` fields into ascii numbers.
/// 4. Check `nonce` == Poseidon([highpartPK, lowpartPK, exp, project_id]).
/// 5. Output the public input `highpartPK, lowpartPK, exp, project_id`.
/// 6. Ensure the `email_verified` is `true` in the JWT token.
/// 7. Output the `email` fields into hash.
///
/// Inputs:
/// - `jwt_segments`: Pad the JWT and split it into multiple segments to boost efficiency.
/// - `jwt_sha256`: The SHA256 hash of the JWT.
/// - `nonce`: Extract the base64 byte array of the `nonce` field from the JWT, verify the correctness.
/// - `email`: Extract the base64 byte array of the `email` field from the JWT.
/// - `email_verified`: Extract the base64 byte array of the `email_verified` field from the JWT.
/// - `email_loc`: The position of `email` in the JWT.
/// - `nonce_loc`: The position of `nonce` in the JWT.
/// - `email_verified_loc`: The position of `email_verified` in the JWT.
/// - `signature`: Convert the Base64-encoded JWT signature string to a BigInt array that can be processed by the Circom circuit.
/// - `modulus`: Extract the JWT `kid` field in the header to apply to the Google API for the public key to verify the JWT signature.
/// - `highpartPK, lowpartPK`: Custom solana public key of Bigint type. 
/// - `exp`: Custom public input as a preimage of the `nonce`.
/// - `project_id`: Custom public input as a preimage of the `nonce`.
///
/// Outputs:
/// - `email_out_ascii_hash`: The hash value of the `email` field. Details refer to the output document.

template ZKLogin(
  nonce_claim_bytes,
  email_claim_bytes,
  email_verified_claim_bytes,
  nonce_bytes,
  email_bytes,
  email_verified_bytes,
  jwt_chunk_size,
  chunk_count,
  n, k
){  
    // input signals
    signal input jwt_segments[chunk_count][jwt_chunk_size]; // split jwt into chunk_count chunks of jwt_chunk_size
    signal input jwt_sha256[256];
    signal input nonce[nonce_claim_bytes];//Nonce, the plaintext length is tentatively set to 79
    signal input email[email_claim_bytes]; // email
    signal input email_verified[email_verified_claim_bytes]; // email_verified
    signal input email_loc;
    signal input nonce_loc;
    signal input email_verified_loc;
    signal input signature[k];
    signal input modulus[k]; 

    signal input highpartPK; // public input
    signal input lowpartPK; // public input
    signal input exp; // public input
    signal input project_id; // public input


    // output signals
    signal output email_out_ascii_hash;

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
    // 2.2 email claims inclusions
    signal email_ascii[email_bytes] <== ClaimInclusion(
      email_claim_bytes, email_bytes, jwt_chunk_size, chunk_count
    )(jwt_segments, email, email_loc);

    signal move_temp_email[41];
    signal email_num[40];
    signal isColon_email_0 <== IsEqual()([email_ascii[0],58]); 
    signal isColon_email_1 <== IsEqual()([email_ascii[1],58]); 
    signal isQuote_email_0 <== IsEqual()([email_ascii[0],34]); 
    signal isQuote_email_1 <== IsEqual()([email_ascii[1],34]); 

    component mux1_email[41];
    component mux2_email[40];
    for(var i = 0; i < 41; i++ ){
        mux1_email[i] = Mux1(); 
        mux1_email[i].c[0] <== email_ascii[i];
        mux1_email[i].c[1] <== email_ascii[i+1];
        mux1_email[i].s <== isColon_email_0 + isQuote_email_0; 
        move_temp_email[i] <== mux1_email[i].out;
    }
    for(var i = 0; i < 40; i++ ){
        mux2_email[i] = Mux1(); 
        mux2_email[i].c[0] <== move_temp_email[i];
        mux2_email[i].c[1] <== move_temp_email[i+1];
        mux2_email[i].s <== isColon_email_1 + isQuote_email_1; 
        email_num[i] <== mux2_email[i].out;
    }
    signal email_out_ascii[2];
    component concat_email[2];
    concat_email[0] = ConcatDigits(3, 21); //Set each ASCII to 3 bits and splice them together. So the first number must be three digits, manually set to 200
    concat_email[1] = ConcatDigits(3, 21); 
    concat_email[0].digits[0] <== 200;
    concat_email[1].digits[0] <== 200;
    for (var i = 1; i < 21; i++) {
        concat_email[0].digits[i] <== email_num[i-1];//email_num[0:20]
        concat_email[1].digits[i] <== email_num[i+19];//email_num[20:40]
    }
    email_out_ascii[0] <== concat_email[0].result;
    email_out_ascii[1] <== concat_email[1].result;

    component email_hash = Poseidon(2);
    email_hash.inputs[0] <== email_out_ascii[0];
    email_hash.inputs[1] <== email_out_ascii[1];
    email_out_ascii_hash <== email_hash.out;

    //-------------------------------------------
    // 2.3 email_verified claims inclusions
    signal email_verified_ascii[email_verified_bytes] <== ClaimInclusion(
      email_verified_claim_bytes, email_verified_bytes, jwt_chunk_size, chunk_count
    )(jwt_segments, email_verified, email_verified_loc);

    component is_equal[12];
    signal find_true[3];
    is_equal[0] = IsEqual(); 
    is_equal[0].in[0] <== email_verified_ascii[0];
    is_equal[0].in[1] <== 116;
    is_equal[1] = IsEqual(); 
    is_equal[1].in[0] <== email_verified_ascii[1];
    is_equal[1].in[1] <== 114;
    is_equal[2] = IsEqual(); 
    is_equal[2].in[0] <== email_verified_ascii[2];
    is_equal[2].in[1] <== 117;
    is_equal[3] = IsEqual(); 
    is_equal[3].in[0] <== email_verified_ascii[3];
    is_equal[3].in[1] <== 101;
    find_true[0] <== is_equal[0].out + is_equal[1].out + is_equal[2].out + is_equal[3].out;

    is_equal[4] = IsEqual(); 
    is_equal[4].in[0] <== email_verified_ascii[1];
    is_equal[4].in[1] <== 116;
    is_equal[5] = IsEqual(); 
    is_equal[5].in[0] <== email_verified_ascii[2];
    is_equal[5].in[1] <== 114;
    is_equal[6] = IsEqual(); 
    is_equal[6].in[0] <== email_verified_ascii[3];
    is_equal[6].in[1] <== 117;
    is_equal[7] = IsEqual(); 
    is_equal[7].in[0] <== email_verified_ascii[4];
    is_equal[7].in[1] <== 101;
    find_true[1] <== is_equal[4].out + is_equal[5].out + is_equal[6].out + is_equal[7].out;

    is_equal[8] = IsEqual(); 
    is_equal[8].in[0] <== email_verified_ascii[2];
    is_equal[8].in[1] <== 116;
    is_equal[9] = IsEqual(); 
    is_equal[9].in[0] <== email_verified_ascii[3];
    is_equal[9].in[1] <== 114;
    is_equal[10] = IsEqual(); 
    is_equal[10].in[0] <== email_verified_ascii[4];
    is_equal[10].in[1] <== 117;
    is_equal[11] = IsEqual(); 
    is_equal[11].in[0] <== email_verified_ascii[5];
    is_equal[11].in[1] <== 101;
    find_true[2] <== is_equal[8].out + is_equal[9].out + is_equal[10].out + is_equal[11].out;
    signal find_true_sum <== find_true[0] + find_true[1] + find_true[2];
    find_true_sum === 4;
    find_true[0] * find_true[1] === 0;
    find_true[0] * find_true[2] === 0;
    find_true[1] * find_true[2] === 0;
}


component main{ public [project_id, highpartPK, lowpartPK, exp]} = ZKLogin(108, 56, 8, 79, 42, 6, 16, 64, 121, 17);
