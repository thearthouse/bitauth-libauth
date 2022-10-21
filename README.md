# bitauth-libauth
added some extra func to https://github.com/bitauth/libauth

secp256k1.BatchPublicKeyUncompressed(pointA,pointB); // returns 100k batch add list pubs in bytes
secp256k1.BatchKeyMullUncompressed(privkeysbuf);  // returns 100k batch calc list pubs in bytes
#works only for uncompressed