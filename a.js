function getrandbits(k) {
  var numbits = new Array(k).fill(1).map(x => Math.round(Math.random())).join('');
  return BigInt("0b"+numbits);
}
function bits_randint(min,max){
  var bigwidth = max-min;
  var klen = bigwidth.toString(2).length;
  var r = getrandbits(klen);
  while (r >= bigwidth){
      r = getrandbits(klen);
  }
  return min+r;
}


const { instantiateSecp256k1 } = require('./libauth');


(async () => {
const secp256k1 = await instantiateSecp256k1();
var priv = Buffer.from('0000000000000000000000000000000000000000000000000000000000000001','hex');
//var G = Buffer.from(secp256k1.derivePublicKeyCompressed(priv)).toString('hex');
var G = secp256k1.derivePublicKeyCompressed(priv);
var b = G;
//console.log(secp256k1);
var dr=10000000000;
var unix = Math.round(+new Date()/1000);
console.time('rand');
for (let i = 1; i < dr; i++) {
//b=ecc.pointAdd(b,G);
  var c = bits_randint(BigInt(1546165),BigInt(15461655616516561654613666666666666566666666666666516)).toString(16).padStart(64, '0');
priv = Buffer.from(c,'hex');
b=secp256k1.derivePublicKeyCompressed(priv);
if ((i%100000)==0){
  var unixx = Math.round(+new Date()/1000);
console.log(i/(unixx-unix));
}
}
console.timeEnd('rand');
var unixx = Math.round(+new Date()/1000);
console.log(dr/(unixx-unix));
console.log((unixx-unix));
})(); 