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
      var G = secp256k1.derivePublicKeyUncompressed(priv);
      var b = G;
      var d;
      var c = bits_randint(BigInt(1),BigInt(2500000)); 
      priv = Buffer.from(c.toString(16).padStart(64, '0'),'hex');
      var find = Buffer.from(secp256k1.derivePublicKeyUncompressed(priv)).toString('hex');
      //console.log(secp256k1);
      var dr=10000000000;
      var unix = Math.round(+new Date()/1000);
      console.time('rand');
      var cdn = 0;
      var ddd;
      var hexb;
      var bsize = 100000;
      const privbuf = new Uint8Array(bsize*32);
      const privdata = {};
      for (let i = 1; i < dr; i++) {
          for (let h = 0; h < bsize; h++) {
            privdata[h]=bits_randint(BigInt(1),BigInt(250000000));
            privbuf.set(Buffer.from(privdata[h].toString(16).padStart(64, '0'),'hex'), h*32);
          }
          d = secp256k1.BatchKeyMullUncompressed(privbuf);
      
      for (let sat = 0; sat < bsize; sat++) {
        ddd =  d.slice((sat*65),(sat*65)+65);
        hexb = Buffer.from(ddd).toString('hex');
        if(find==hexb){
            console.log(hexb+" "+(privdata[sat]==c)+" "+privdata[sat]+"  "+d.length/65);
            throw 'key found!';
        }
      }
      cdn += bsize;
      if ((cdn%1500000)==0){
        var unixx = Math.round(+new Date()/1000);
      console.log(cdn/(unixx-unix));
      //console.log(Buffer.from(d.slice(0,65)).toString('hex'));
      //console.log(d.slice(0,66));
      }
      }
      console.timeEnd('rand');
      var unixx = Math.round(+new Date()/1000);
      console.log(dr/(unixx-unix));
      console.log((unixx-unix));
  })(); 