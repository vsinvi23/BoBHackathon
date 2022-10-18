/*!
 * @fileOverview Javascript Utility class (Util.js)
 * @author DS3, http://www.ds3global.com
 * @version 1.0
 */

  
/**
 * Creates a new Utility Object
 * @class Represents a utility class 
 */ 
 
function Util(){}

/**
 *  Convert a string to a big integer object.
 *  @param {String} str Data string.
 *  @param {int} r  Radix e.g., 16(Hex string).
 *  @returns {BigInteger} Big integer representation of data string.
 */
Util.parseBigInt=function(str,r){
  return new BigInteger(str,r);
}

/**
 *  Fold SHA256 32 byte HASH into 16 byte by perform XOR on N XOR N+16
 *  Input must be 32 bytes array
 *  @param {Array} SHA256 HASH byte Array
 *  @returns {Array} folded byte array of length 16
 */
Util.foldSHA256To16Bytes =function(hashBytes)
{
    var pwdBytes = new Array(16);
    for(var i=0; i<16; i++){
        pwdBytes[i] = hashBytes[i] ^ hashBytes[i+16];
    }
    return pwdBytes;
}

/**
 *  Count number of complete bytes in hex string.
 *  If there is a nibble on the end of the HexString it will be ignored.
 *  @param {hexString}.
 *  @returns count in HexString
 */
Util.countBytes=function(HexString){
  var length= ~~(HexString.toString(16).length/2);
  return length <= 15 ? "0" + length.toString(16) : length.toString(16);
}

/**
 *  Generate a random bytes of specified byte length. Random value will be from 0 to 255.
 *  @param {int} numOfBytes Number of bytes.
 *  @return {Array} Random bytes generated stored in array.
 */
Util.randomBytes=function(numOfBytes){
   var cryptoObj = window.crypto || window.msCrypto; // for IE 11
   var typedRndArr = new Uint8Array(numOfBytes);
   cryptoObj.getRandomValues(typedRndArr);

   normalRndArr = Array.prototype.slice.call(typedRndArr);
   normalRndArr.length === numOfBytes;
   normalRndArr.constructor === Array;

   return normalRndArr;
}

/**
 *  Generate a random string of specified byte length.
 *  @param {int} numOfBytes Length of random string.
 *  @return {String} Random string of requested length.
 */
Util.randomString=function(numOfBytes){
    var rndString = "";
    var rndArr = Util.randomBytes(numOfBytes); // get an array of random numbers
    if (!rndArr || (rndArr.length < numOfBytes)){
        alert("Random not generated");
        return null;
    }

    rndString = String.fromCharCode.apply(null, rndArr);
    return rndString;
}



/**
 * Encode hex string encoded from byte array.
 * @param {Array} byteArr Array to encode to hex string.
 * @returns {String} Hex string encoding of input array. 
 */
Util.toHexString=function(byteArr){
    var str = "";
    for(var i=0; i<byteArr.length;i++){
        
        var ch;
        if(typeof byteArr[i] == "number"){
            ch = (byteArr[i]).toString(16);
        }else if(typeof byteArr[i] == "string"){
            ch = byteArr.charCodeAt(i).toString(16);
        }
        if(ch.length==1) ch = "0"+ch;
        str += ch;
    }
    return str;
}

/**
 * Return byte array encoded from input hex string.
 * @param {String} hexStr Input hex string
 * @returns {Array} Byte array encoded from input hex string 
 */
Util.fromHexString=function(hexStr){
    hexStr = (hexStr.length%2 == 0) ? hexStr : "0"+hexStr;
    var len = hexStr.length / 2;
    var str = [];
    for (var i=0, j=0; i<len; i++,j++){
        var start = i*2;
        str[j] = parseInt("0x"+hexStr.substring(start,start+2));
    }
    return str;
}



//Convert byte array into native byte string(2^8)
//Convert back to byte array via getByteArray function

/**
* Convert byte array into native string.
* @param {Array} byteArr Byte array to be representated in native string.
* @return {String} Native string representation.
*/
Util.cByteArrayToNString=function(byteArr){
  var x = "";
  for(var i=0;i<byteArr.length;i++){
      //alert(byteArr[i]);
      x+=String.fromCharCode(byteArr[i]);
  }
  return x;
}

//converts string to array of bytes to be converted in to BIG Integer
//Special for RSA only.

/**
* Return byte array representation of native string.
* @param {String} s Native string to be representated in byte array.
* @return {Array} Byte array representation.
*/
Util.getByteArray=function(s){
  a = new Array();
  for (var i = 0 ; i < s.length; i++){
      a[i] = s.charCodeAt(i);
  }
  return a;
}

/**
 * XOR two byte array then return result in byte array.
 * @param {Array} a Operand byte array 1.
 * @param {Array} b Operand byte array 2.
 */
Util.xorByteArray=function(a,b){
    if(a.length > b.length) throw "Invalid parameters.";
    var x = [];
    for(var i=0; i<a.length; i++)
        x[i] = a[i] ^ b[i];
    return x;
}

/**
 * Convert hex string to native string.
 * @param {String}  hexStr  Hex string to be converted.
 * @return {String} Native string representation.
 */
Util.fromHexToString=function(hexStr){
	hexStr = (hexStr.length%2 == 0) ? hexStr : "0"+hexStr;
	var len = hexStr.length / 2;
	var str = "";
	for (var i=0; i<len; i++){
		var start = i*2;
		str = str + String.fromCharCode (parseInt("0x"+hexStr.substring(start,start+2)) );
	}
	return str;
}

/**
 * Convert native string to hex string.
 * @param {Array} s Native string to be represented in hex string.
 * @return {String} Hex string representation.
 */
Util.stringToHex=function(s) {
  var r = "";
  var hexes = new Array ("0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f");
  for (var i=0; i<s.length; i++) {r += hexes [s.charCodeAt(i) >> 4] + hexes [s.charCodeAt(i) & 0xf];}
  return r;
}
