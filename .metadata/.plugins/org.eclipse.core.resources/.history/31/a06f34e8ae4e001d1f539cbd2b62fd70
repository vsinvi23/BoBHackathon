/*!
 * @fileOverview Javascript RSA implementation(rsa.js)
 * @version 1.6
 */

/*!
 * This package includes code written by Tom Wu.
 *
 * Copyright (c) 2003-2005  Tom Wu
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 */
/*!
 * Copyright (c) 2003-2005  Tom Wu
 * http://www-cs-students.stanford.edu/~tjw/jsbn/
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY
 * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
 *
 * IN NO EVENT SHALL TOM WU BE LIABLE FOR ANY SPECIAL, INCIDENTAL,
 * INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND, OR ANY DAMAGES WHATSOEVER
 * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER OR NOT ADVISED OF
 * THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF LIABILITY, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * In addition, the following condition applies:
 *
 * All redistributions must retain an intact copy of this copyright notice
 * and disclaimer.
 */


// Depends on jsbn.js and rng.js
// convert a (hex) string to a bignum object
function parseBigInt(str,r) {
    return new BigInteger(str,r);
}
/*
function linebrk(s,n) {
  var ret = "";
  var i = 0;
  while(i + n < s.length) {
    ret += s.substring(i,i+n) + "\n";
    i += n;
  }
  return ret + s.substring(i,s.length);
}
 */
/*
function byte2Hex(b) {
  if(b < 0x10)
    return "0" + b.toString(16);
  else
    return b.toString(16);
}
 */

// Version 6.1c #2
// Citibank old PKCS#1
// PKCS#1 (type 2, random) pad input string s to n bytes, and return a bigint
// n, number of bytes
// plaintext, bytes of data
// changed to accept input as byte array not bigInteger
// For Function rsaEncryptPIN, rsaEncrypt

function pkcs1pad2B(dataBytes, n){
    var numOfBytes = dataBytes.length;
    //console.log("numOfBytes:"+numOfBytes);

    // Formatting for Citibank PKCS#1
    // | 0x00 | 0x02 | Citibank custom { 0xFF | 0xFF | 0xFF | 0xFF } | PS (min 8 bytes) | 0x00 | Message |

    if(numOfBytes > n - 11 - 4){
        throw "104";	// message too long for RSA
    }

    var result = [0x00, 0x02, 0xFF, 0xFF, 0xFF, 0xFF];
    var PS_Size = n - numOfBytes - 3 - 4;
    //console.log("PS_Size:"+PS_Size);

    var PS = randomBytes(PS_Size);
    if (!PS || (PS.length < PS_Size)){
        alert("Random bytes array not generated");
        return null;
    }
    //console.log("PS.length:"+PS.length);
    //console.log("PS:"+PS);

    var final_padded = result.concat(PS, [0x00], dataBytes);

    //console.log("final_padded.length:"+final_padded.length);
    //console.log("final_padded:"+final_padded);

    var padded = new BigInteger(final_padded);
    return padded;

}

// Create random byte array
function randomBytes(numOfBytes){
    var cryptoObj = window.crypto || window.msCrypto; // for IE 11
    var typedRndArr = new Uint8Array(numOfBytes);
    cryptoObj.getRandomValues(typedRndArr);
    normalRndArr = Array.prototype.slice.call(typedRndArr);
    normalRndArr.length === numOfBytes;
    normalRndArr.constructor === Array;
    return normalRndArr;
}

// Version 1~6.1b #1
// PKCS#1
// PKCS#1 (type 2, random) pad input string s to n bytes, and return a bigint
// For Function encryptPIN

function pkcs1pad2(plainText,n) {

    //According to PKCS, the limit  s + 11 <= n,
    //but added 4 bytes for 0xFFFFFFFF
    var txtSize = Math.ceil(plainText.bitLength()/8);
    //console.log('n: '+n+' txtsize: '+txtSize);
    
    if(n < txtSize + 11) {
        alert("Message too long for RSA");
        return null;
    }

    //Header with large Random
    var header = [0x00, 0x02];
    var randomSize;
    randomSize = n - txtSize - 3; //3 + 4 for same reasons above

    //console.log('randomSize: '+randomSize);
    
    var i=2;

    //Padd with random in the center
    while(i < randomSize+2){
        var x = 0;
        while(x == 0){//random cannot be zero to avoid denote
        var rndArray = randomBytes(1);
        if(!rndArray || (rndArray.length < 1)){
            alert("Random Number not generated");
            return null;
        }
        
        x = rndArray[0];
        }
        header [i++] = x;
    }
    
    //console.log('header: '+header.length);
    
    var biHeader = new BigInteger(header);
    
    //console.log('biHeader: '+biHeader.toString(16));
    
    var paddedMsg = biHeader.toString(16) + "00" + plainText.toString(16) ;//00 is the denote

    //console.log('paddedMsg: '+paddedMsg);
    
    return new BigInteger(paddedMsg,16);
}

/**
 * RSA Standard PKCS#1
 * @param plainText BigInteger of data
 * @param n         length of rsa key in byte
 */
function pkcs1pad2S(plainText,n) {

    //According to PKCS, the limit  s + 11 <= n,
    //but added 4 bytes for 0xFFFFFFFF
    var txtSize = Math.ceil(plainText.bitLength()/8);
    if(n < txtSize + 11) {
        alert("Message too long for RSA");
        return null;
    }

    //Header with large Random
    var header = [0x00, 0x02];
    var randomSize;
    randomSize = n - txtSize - 3;

    var i=2;

    //Padd with random in the center
    while(i<randomSize+2){
        var x = 0;
        while(x == 0){//random cannot be zero to avoid denote
            var rndArray = randomBytes(1);
            if(!rndArray || (rndArray.length < 1)){
                alert("Random not generted");
                return null;
            }
            x = rndArray[0];
        }
        header [i++] = x;
    }

    var biHeader = new BigInteger(header);
    var paddedMsg = biHeader.toString(16) + "00" + plainText.toString(16) ;//00 is the denote

    return new BigInteger(paddedMsg,16);
}

// RSA Standard PKCS#1
// PKCS#1 (type 2, random) pad s(input string) to n bytes, and return a bigint
/*
function pkcs1pad2(s,n) {
  if(n < s.length + 11) { // TODO: fix for utf-8
    alert("Message too long for RSA");
    return null;
  }
  var ba = new Array();
  var i = s.length - 1;
  while(i >= 0 && n > 0) {
    var c = s.charCodeAt(i--);
    if(c < 128) { // encode using utf-8
      ba[--n] = c;
    }
    else if((c > 127) && (c < 2048)) {
      ba[--n] = (c & 63) | 128;
      ba[--n] = (c >> 6) | 192;
    }
    else {
      ba[--n] = (c & 63) | 128;
      ba[--n] = ((c >> 6) & 63) | 128;
      ba[--n] = (c >> 12) | 224;
    }
  }
  ba[--n] = 0;
  var rng = new SecureRandom();
  var x = new Array();
  while(n > 2) { // random non-zero pad
    x[0] = 0;
    while(x[0] == 0) rng.nextBytes(x);
    ba[--n] = x[0];
  }
  ba[--n] = 2;
  ba[--n] = 0;
  return new BigInteger(ba);
}
 */

// "empty" RSA key constructor
function RSAKey() {
    this.n = null;
    this.e = 0;
    this.d = null;
    //this.p = null;
    //this.q = null;
    //this.dmp1 = null;
    //this.dmq1 = null;
    //this.coeff = null;
}

// Set the public key fields N and e from hex strings
//function RSASetPublic(N,E) {
RSAKey.prototype.setPublic=function(N,E){
    if(N != null && E != null && N.length > 0 && E.length > 0) {
        this.n = parseBigInt(N,16);
        this.e = parseInt(E,16);
    }
    else alert("Invalid RSA public key");
}

// Perform raw public operation on "x": return x^e (mod n)
//function RSADoPublic(x) {
RSAKey.prototype.doPublic=function(x){
    return x.modPowInt(this.e, this.n);
}


/**
 *  @param dataHexStr data hex string
 */
RSAKey.prototype.encryptNativeHexStr=function(dataHexStr){
    var numOfBytes = dataHexStr.length/2;
    //alert("n:"+this.n);

    var n = (this.n.bitLength()+7)>>3;  //number of bytes in public key
    //alert("numOfBytes:"+numOfBytes+" n:"+n);
    if(numOfBytes > n){
        throw "104"; // message too long for RSA
    }

    var m = new BigInteger(dataHexStr, 16);
    //alert("m:"+m);
    //alert("compare:"+m.compareTo(this.n));


    var c = this.doPublic(m);
    if(c == null) return null;
    var h = c.toString(16);
    //Check if length is less than 256
    //if((h.length & 1) == 0) return h; else return "0" + h;

    if(h.length>256) return null;
    if(h.length<256){
        for(var i=0; i<(256 - h.length); i++) h= "0"+h;
    }
    return h;
}


/**
 *  @param dataBytes data hex string
 */
RSAKey.prototype.encryptNativeBytes=function(dataBytes){
    var numOfBytes = dataBytes.length;
    //alert("n:"+this.n);

    var n = (this.n.bitLength()+7)>>3;  //number of bytes in public key
    //alert("numOfBytes:"+numOfBytes+" n:"+n);
    if(numOfBytes > n){
        throw "104"; // message too long for RSA
    }

    var m = new BigInteger(dataBytes);
    //alert("m:"+m);

    var c = this.doPublic(m);
    if(c == null) return null;
    var h = c.toString(16);
    //Check if length is less than 256
    //if((h.length & 1) == 0) return h; else return "0" + h;

    if(h.length>256) return null;
    if(h.length<256){
        for(var i=0; i<(256 - h.length); i++) h= "0"+h;
    }
    return h;
}

/**
 * RSA encryption
 * @param plainText
 */
RSAKey.prototype.encryptS=function(plainText){

    var m  = pkcs1pad2S(plainText,(this.n.bitLength()+7)>>3) ;
    if(m == null) return null;
    var c = this.doPublic(m);
    if(c == null) return null;
    var h = c.toString(16);
    //Check if length is less than 256
    //if((h.length & 1) == 0) return h; else return "0" + h;
    if(h.length>256) return null;
    if(h.length<256){
        for(var i=0; i<(256 - h.length); i++) h= "0"+h;
    }
    return h;
}


// Return the PKCS#1 RSA encryption of plaintext as an even-length hex string
// Only can cater for 128-(11+4) = 113 bytes of data
//function RSAEncrypt(plainText) {
// process input as BigInteger
// For function encryptPIN

RSAKey.prototype.encrypt=function(plainText){

	var modLengthInByte = (this.n.bitLength()+7)>>3;
	
	//console.log("modLengthInByte: "+modLengthInByte);
	
    var m  = pkcs1pad2(plainText, modLengthInByte) ;
    if(m == null) return null;
    //console.log("m: "+m.toString(16));
   
    var c = this.doPublic(m);
    if(c == null) return null;
    var h = c.toString(16);
    
    //console.log('h: '+h);
    //console.log('h len: '+h.length);
    
    //Check if length is less than 256
    //if((h.length & 1) == 0) return h; else return "0" + h;

    if(h.length > modLengthInByte*2) return null;
    
    var fill = "";
	if(h.length < modLengthInByte*2){ 
		for(var ii=0; ii < (modLengthInByte*2 - h.length); ii++) { 
			fill=fill.concat("0");
		}
	}
	
	return fill.concat(h);
}


// Process input as databytes
// For function rsaEncryptPin & rsaEncrypt

RSAKey.prototype.encryptB=function(dataBytes){

    var m  = pkcs1pad2B(dataBytes,(this.n.bitLength()+7)>>3);
    if(m == null) return null;
    var c = this.doPublic(m);
    if(c == null) return null;
    var h = c.toString(16);
    //Check if length is less than 256
    //if((h.length & 1) == 0) return h; else return "0" + h;

    if(h.length>256) return null;
    
    var fill = "";
	if(h.length<256){ 
		for(var ii=0; ii<(256 - h.length); ii++) { 
			fill=fill.concat("0");
		}
	}
	return fill.concat(h);
}

// Return the PKCS#1 RSA encryption of "text" as a Base64-encoded string
//function RSAEncryptB64(text) {
//  var h = this.encrypt(text);
//  if(h) return hex2b64(h); else return null;
//}

// protected
//RSAKey.prototype.doPublic = RSADoPublic;

// public
//RSAKey.prototype.setPublic = RSASetPublic;
//RSAKey.prototype.encrypt = RSAEncrypt;

//RSAKey.prototype.encrypt_b64 = RSAEncryptB64;
