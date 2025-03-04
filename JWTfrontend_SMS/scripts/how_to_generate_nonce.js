const buildPoseidon = require("circomlibjs").buildPoseidon;
const buildEddsa =require("circomlibjs").buildEddsa;

let poseidon;
(async () => {
    eddsa = await buildEddsa();
    const F = eddsa.babyJub.F;
    poseidon = await buildPoseidon();

    let exp = "1740656756";//时间戳例子（前端输入）
    let project_id = "10006"; //项目ID例子（前端输入）

    // 对exp进行BigInt转换
    let exp_bigint = BigInt(exp).toString();

    let highpartPK = "190382143502568173121953655840023021428";
    let lowpartPK = "268907290496916820827766377268916025917";

    let nonce = poseidon([highpartPK, lowpartPK, exp_bigint, project_id]);//这里不加这个[]会报错
    console.log("nonce: "+F.toObject(nonce));//这里是输出明文形式的hash值

})();
