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
  
  
  const { instantiateSecp256k1,instantiateSha256 } = require('./libauth');
  
  
  (async () => {
      const secp256k1 = await instantiateSecp256k1();
      const shan = await instantiateSha256();
      var priv = Buffer.from('0000000000000000000000000000000000000000000000000000000000000001','hex');
      //var G = Buffer.from(secp256k1.derivePublicKeyCompressed(priv)).toString('hex');
      var G = secp256k1.derivePublicKeyUncompressed(priv);
      var b = G;
      var d;
      var c = bits_randint(BigInt(1),BigInt(25000000)); 
      priv = Buffer.from(c.toString(16).padStart(64, '0'),'hex');
      var find = Buffer.from(secp256k1.derivePublicKeyUncompressed(priv)).toString('hex');
      //console.log(secp256k1);
      var dr=10000000000;
      var unix = Math.round(+new Date()/1000);
      console.time('rand');
      var cdn = 0;
      var ddd;
      var hexb;
      var bsize = 10000;
      const privbuf = new Uint8Array(bsize*32);
      const privdata = {};
      for (let i = 1; i < dr; i++) {
        var priv0 = Buffer.from(i.toString(),'utf-8');
        var b=Buffer.from(shan.hash(priv)).toString('hex');
      cdn += 1;
      if ((cdn%100000)==0){
        var unixx = Math.round(+new Date()/1000);
      console.log(cdn/(unixx-unix));
      //console.log(Buffer.from(d.slice(0,65)).toString('hex'));
      //console.log(d.slice(0,66));
      }
      }
  })(); 