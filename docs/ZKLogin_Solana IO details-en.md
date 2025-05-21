# Workflow

The following description applies to the circuit version that uses the OAuth public key as a public input.
### ![Workflow](./img/workflow.png)
# Oracle Service Overview

The off‐chain Oracle is responsible for updating the Google OAuth public key in the AA contract so that the AA contract can obtain the associated Google public key from the public outputs of Proof Verify. Its specific duties include:

1.	Periodically fetch the latest Google public key data
2.	Check the current on‐chain public key data, and if an update is detected, refresh the public key

# JWT Payload Example

## Scenario 1: SMS

Below is a sample JWT payload:
```
{
  "authNonce": "8205186017709859508660632939999119337571865072490932098058920183355571410508",
  "iss": "https://securetoken.google.com/sklogin-35f26",
  "aud": "sklogin-35f26",
  "phone_number": "+8618373233872",
}
```

### Input Parameters and Processing Flow

This JWT, together with the following parameters, is used as input to a front‐end script that generates `ZKLogin_solana.json`, which is then fed to the prover to generate proof and witness:

- `highpartPK`  
- `lowpartPK`  
- `exp`  
- `project_id`

Assume in `scripts/generate_circuit_input.js` the variable inputs are:

```javascript
highpartPK = 190382143502568173121953655840023021428n
lowpartPK = 268907290496916820827766377268916025917n
exp_bigint = 1740656756
project_id = 10006
```

### Witness Generation Example

The above payload yields the following witness (an array of 25 `bigints`):

```
[
200104116116112115058047047115101099117114101116111107101110046103111
200111103108101046099111109047115107108111103105110045051053102050054
200115107108111103105110045051053102050054
7127763890147960849159333201500040230637305205035149584967442789098807458525
2024841858879950664723963975520030095
2293833913901965663562099879360742582
2085108161076800855610772977535489999
1762734634379572515266880802235119430
447057840158440830007440102626333749
843095074245726941310573529101012953
738318145350872802234100178275232129
1106464730208335804736890163997055636
140698508067250351635990938213217450
1281754911449244346861965017515071285
697896204939881489419392511490512460
949220696447986452985237154413389046
1465493978489733978776055851658825470
1367803428989297115153162323044294701
2549269324917634684569239908306733183
1368860182273110044392825175159449559
3771557191587409074449566276496256
190382143502568173121953655840023021428
268907290496916820827766377268916025917
1740656756
10006
]
```

### Witness Field Definitions

1. **`witness[0]`**  
   Rule: `'200'` + concatenation of three‐digit ASCII codes for the first 22 characters of `iss`  
   Example:  
   - First 22 chars of `iss`: `https://securetoken.go`  
   - ASCII codes: `104116116112115058047047115101099117114101116111107101110046103111`  
   - Final value: `200` + above → `200104116116112115058047047115101099117114101116111107101110046103111`

2. **`witness[1]`**  
   Rule: `'200'` + concatenation of three‐digit ASCII codes for characters 23–44 of `iss`  
   Example:  
   - Chars 23–44 of `iss`: `ogle.com/sklogin-35f26`  
   - ASCII codes: `111103108101046099111109047115107108111103105110045051053102050054`  
   - Final value: `200` + above → `200111103108101046099111109047115107108111103105110045051053102050054`

3. **`witness[2]`**  
   Rule: `'200'` + concatenation of three‐digit ASCII codes for the first 13 characters of `aud`  
   Example:  
   - First 13 chars of `aud`: `sklogin-35f26`  
   - ASCII codes: `115107108111103105110045051053102050054`  
   - Final value: `200` + above → `200115107108111103105110045051053102050054`

4. **`witness[3]`**  
   Rule: Poseidon hash of the ASCII codes of `phone_number`, padded with `00` to length 16×2  
   Example:  
   - `phone_number`: `+8618373233872`  
   - ASCII + `00` padding to 32 chars: `43565449565155515051515655500000`  
   - Poseidon hash: `7127763890147960849159333201500040230637305205035149584967442789098807458525`

5. **`witness[4]–witness[20]`**  
   Rule: JWT signature public key, as 17 bigints

6. **Subsequent fields**  
   - `witness[21]` → `highpartPK`  
   - `witness[22]` → `lowpartPK`  
   - `witness[23]` → `exp`  
   - `witness[24]` → `project_id`

7. **For `witness[0]–witness[2]`, if the string length is insufficient, pad with `000` to length (field_length+1)×3**  
   Example for `witness[2]`: if `aud` = `abc` (3 chars, needs 13):  
   - ASCII codes: `097098099`  
   - Value: `200` + above → `200097098099`  
   - Padded to (13+1)×3 = 42 digits:  
     `200097098099000000000000000000000000000000`

## Scenario 2: EMAIL

Below is a sample JWT payload:
```
{
  "authNonce": "8205186017709859508660632939999119337571865072490932098058920183355571410508",
  "iss": "https://securetoken.google.com/sklogin-35f26",
  "aud": "sklogin-35f26",
  "email": "laonianrencaozuo@gmail.com",
}
```
The above payload produces the following witness (an array of 25 `bigint`):

```
[
200104116116112115058047047115101099117114101116111107101110046103111
200111103108101046099111109047115107108111103105110045051053102050054
200115107108111103105110045051053102050054
8221293801905454488570447792679227103271972158867850021273786099763738695508
2024841858879950664723963975520030095
2293833913901965663562099879360742582
2085108161076800855610772977535489999
1762734634379572515266880802235119430
447057840158440830007440102626333749
843095074245726941310573529101012953
738318145350872802234100178275232129
1106464730208335804736890163997055636
140698508067250351635990938213217450
1281754911449244346861965017515071285
697896204939881489419392511490512460
949220696447986452985237154413389046
1465493978489733978776055851658825470
1367803428989297115153162323044294701
2549269324917634684569239908306733183
1368860182273110044392825175159449559
3771557191587409074449566276496256
190382143502568173121953655840023021428
268907290496916820827766377268916025917
1740656756
10006
]
```

### Witness Field Specification

1. **`witness[0]`**  
   Rule: `'200'` + concatenation of three-digit ASCII codes for the first 22 characters of `iss`  
   Example:  
   - First 22 chars of `iss`: `https://securetoken.go`  
   - ASCII codes: `104116116112115058047047115101099117114101116111107101110046103111`  
   - Final value: `200` + above → `200104116116112115058047047115101099117114101116111107101110046103111`

2. **`witness[1]`**  
   Rule: `'200'` + concatenation of three-digit ASCII codes for characters 23–44 of `iss`  
   Example:  
   - Chars 23–44 of `iss`: `ogle.com/sklogin-35f26`  
   - ASCII codes: `111103108101046099111109047115107108111103105110045051053102050054`  
   - Final value: `200` + above → `200111103108101046099111109047115107108111103105110045051053102050054`

3. **`witness[2]`**  
   Rule: `'200'` + concatenation of three-digit ASCII codes for the first 13 characters of `aud`  
   Example:  
   - First 13 chars of `aud`: `sklogin-35f26`  
   - ASCII codes: `115107108111103105110045051053102050054`  
   - Final value: `200` + above → `200115107108111103105110045051053102050054`

4. **`witness[3]`**  
   Rule: Poseidon hash of the two elements:  
   - `'200'` + three-digit ASCII codes for the first 20 chars of `email` (pad with `000` to 21×3 if shorter)  
   - `'200'` + three-digit ASCII codes for chars 21–40 of `email` (pad with `000` to 21×3 if shorter)  
   Example (`email = laonianrencaozuo@gmail.com`):  
   - Chars 1–20: `laonianrencaozuo@gma` → ASCII: `108097111110105097110114101110099097111`  
     → prefixed: `200108097111110105097110114101110099097111122117111064103109097`  
   - Chars 21–40: `il.com` → ASCII: `105108046099111109`  
     → padded & prefixed:  
     `200105108046099111109000000000000000000000000000000000000000000`  
   - Poseidon hash of these two →  
     `8221293801905454488570447792679227103271972158867850021273786099763738695508`

5. **`witness[4]–witness[20]`**  
   Rule: JWT signature public key, represented as 17 `bigint` values

6. **Subsequent fields**  
   - `witness[21]` → `highpartPK`  
   - `witness[22]` → `lowpartPK`  
   - `witness[23]` → `exp`  
   - `witness[24]` → `project_id`
