const { instantiateSecp256k1,instantiateSha256 } = require('./libauth');
function pipes() {
  return instantiateSecp256k1();
}
function shan() {
  return instantiateSha256();
}
function puffer() {
  return Buffer;
}

module.exports = {
    pipes,
    shan,
    puffer
}