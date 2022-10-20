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
  var b=secp256k1.addTweakPublicKeyCompressed(G,priv);
  var bun =secp256k1.deriveBatchPublicKeyUncompressed(G,b);
  console.log(Buffer.from(bun).toString('hex'));
})(); 