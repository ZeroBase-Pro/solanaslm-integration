const {generate_data, createInputs} = require('../utils/input');

// ************************
// input your public key here
let highpartPK = ;
let lowpartPK = ;
// ************************
// input your exp here
let exp = "";
// ************************
// input your ID here
let project_id = "";
// ************************
// input your JWT Token here
const jwtToken = ""
// ************************
const data = generate_data(jwtToken);

createInputs(data, highpartPK, lowpartPK, exp, project_id)
  .then(() => {
    console.log('CreateInputs done! Check out `/inputs/ZKLogin_solana_EMAIL.json`');
  })
  .catch((error) => {
    console.error('CreateInputs error:', error);
  });