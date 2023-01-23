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
  
var onnen = BigInt(0);
  (async () => {
  const secp256k1 = await instantiateSecp256k1();
  var priv = Buffer.from('0000000000000000000000000000000000000000000000000000000000000001','hex');
  var ripemd60 = Buffer.from('f6d8ce225ffbdecec170f8298c3fc28ae686df23','hex');
  
  var dr=10000000000;
  var unix = Math.round(+new Date()/1000);
  console.time('rand');
  for (let i = 1; i < dr; i++) {
  //b=ecc.pointAdd(b,G);
    var c = bits_randint(BigInt("0x4aed01170"),BigInt("0x4aed51170"));
    priv = Buffer.from(c.toString(16).padStart(64, '0'),'hex');
    var pubkey = secp256k1.derivePublicKeyUncompressed(priv);
    var b = secp256k1.BatchPublicKeyUncompressed(secp256k1.derivePublicKeyCompressed(priv),ripemd60);
    var g = Buffer.from(b).toString('hex');
    var ff = BigInt('0x'+g);
    if(ff > onnen){
        ff = c+(ff-1n);
        console.log("Faund = "+ff.toString(16));
        break;
    }
  
  /* b=secp256k1.derivePublicKeyCompressed(priv); */
  if ((i%20)==0){
    var unixx = Math.round(+new Date()/1000);
  console.log((i*1000000)/(unixx-unix));
  }
  }
  console.timeEnd('rand');
  var unixx = Math.round(+new Date()/1000);
  console.log(dr/(unixx-unix));
  console.log((unixx-unix));
  })(); 