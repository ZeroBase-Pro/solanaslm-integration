const assert = require("assert");

const toByteArray = (str) => {
  let utf8Encode = new TextEncoder();
  return utf8Encode.encode(str)
}

const findClaimLocation = (jwt, claim, max) => {
  const jwtBytes = toByteArray(jwt);//将 JWT 转换为字节数组

  // generate the text at all possible possible version
  // 尝试多种可能的 Base64 编码形式，包括清除等号的编码形式、带引号的编码形式、带冒号的编码形式
  let clean_test = btoa(claim).replaceAll("=", "");//0
  let quote_at_0_index = btoa(`"${claim}`).replaceAll("=", "");//1
  let colon_at_0_index = btoa(`:${claim}`).replaceAll("=", "");//1
  let quote_and_colon_at_start = btoa(`":${claim}`).replaceAll("=", "");//2
  let colon_and_quote_at_start = btoa(`:"${claim}`).replaceAll("=", "");//2
  let comma_at_the_end = btoa(`${claim},`).replaceAll("=", "");//0
  let quote_at_start_and_end = btoa(`"${claim}"`).replaceAll("=", "");//1
  let quote_and_comma_at_end = btoa(`${claim}",`).replaceAll("=", "");//0
  let comma_and_quote_at_end = btoa(`${claim},"`).replaceAll("=", "");//0
  let colon_at_start_and_comma_at_end =  btoa(`:${claim},`).replaceAll("=", "");//1
  let colon_and_quote_at_start_quote_at_end = btoa(`:"${claim}"`).replaceAll("=", "");//2
  //0: 0,5,7,8   1: 1,2,6,9   2: 3,4,10
  const versions = [
    clean_test, quote_at_0_index, colon_at_0_index, quote_and_colon_at_start, colon_and_quote_at_start, comma_at_the_end,
    quote_at_start_and_end, quote_and_comma_at_end, comma_and_quote_at_end, colon_at_start_and_comma_at_end, colon_and_quote_at_start_quote_at_end,
  ];

  let claimLocation;
  let version = 0;
  
  // 遍历这些编码形式，并在 JWT 中查找这些编码形式的存在位置
  for (let i = 0; i < versions.length; i++) {
    if(jwt.indexOf(versions[i]) !== -1) {
      claimLocation = jwt.indexOf(versions[i]);
      version = versions[i];
      console.log("i:",i);
      console.log("claim",claim);
      break;
    }
  }

  // 将找到的位置的字节与声明的字节逐个比较，确保找到的确实是声明的位置
  let claimBytes = toByteArray(version);
  console.log("version:",version);
  console.log("claimBytes:",claimBytes);
  for (let i = claimLocation, j = 0; i < claimLocation + claimBytes.length; i++, j++) {
    assert(jwtBytes[i] === claimBytes[j]);
  }

  const len = claimBytes.length;
  if (len <= max) {
  // 如果声明的字节数组长度小于最大长度，则用 0 填充
    claimBytes = [...claimBytes, ...new Array(Math.max(max - len, 0)).fill(0)];

  }else{
    // 如果声明的字节数组长度大于最大长度，则截取前面的字节
    claimBytes = Array.from(claimBytes.slice(0, max));
  }

  //表示claim声明的字节数组，经过 Base64 编码和填充到最大长度。它是一个字符串数组，每个元素表示一个字节
  return [claimBytes.map(v => v.toString()), claimLocation]
}


module.exports = {findClaimLocation};
