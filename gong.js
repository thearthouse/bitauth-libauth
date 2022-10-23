var goo = require('./bundle10kpuffer.js');




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
  
  
  
  
  (async () => {
    var secp256k1 = await goo.pipes();
      const duffer = goo.puffer();
      var shanc = await goo.shan();
      var st = "1";
      console.log(duffer.from(shanc.hash(duffer.from(st, 'utf8'))).toString('hex'));
  })(); 