/*!
* @description DSSS JavaScript End-to-End Encryption Package
* @version 1.6.3 (17 September 2018)
* @author Gemalto, http://www.gemalto.com
*/

/**
* <p>DSSS JavaScript End-to-End Encryption Package<br>
* This package contains open source libraries or binaries within its distribution package.
* For more information, please see respectively included license.</p>
* <p>
* Package:<br>
* <ul>
* <li>DSSSCryptography.js</li>
* <li>jsbn.js</li>
* <li>md5.js</li>
* <li>rsa.js</li>
* </ul>
* </p>
*
* <p>Usage: Initialize global variable; Modulus(RSA Public Key), Exponent(RSA Public Key) before calling methods.<br>
* E.g., var Modulus="A8023...0"; var Exponent="10001" </p>
*/

var Modulus, Exponent;

/**
 * @private
 */

function translateVerifyRSABlock( UserIdValue,PinValue, ServerRND)
{
    var s = UserIdValue + PinValue;
    var cnt = Math.ceil (s.length/(ServerRND.length/2));
    //create static old password
    var longrnd = "";
    for (var i = 0 ; i < cnt; i ++) longrnd = longrnd + ServerRND;

    var biUIDPIN = new BigInteger(getByteArray(s));
    longrnd = longrnd.substring (0,s.length*2);//one byte 2 hex digits
    var tmp = new BigInteger(longrnd,16);
    biUIDPIN = biUIDPIN.xor (tmp);
    var len = s.length.toString(16);
    if (s.length <= 0xF) len = "0"+len;
    var block1 = "0B"+ len + biUIDPIN.toString(16);//the new TLV is 0x0B

    //create plain text
    var plaintext = new BigInteger (block1, 16);

    var rsa = new RSAKey();
    rsa.setPublic(Modulus, Exponent);
    var rsablock = rsa.encrypt(plaintext);
    return rsablock.toString(16);
}
/**
 * @private
 */

function translateChangePwdRSABlock( UserIdValue,NEWPIN,OLDPIN,ServerRND)
{
    // the server random is expected 8 bytes
    //create static old password
    var s = UserIdValue + OLDPIN;
    var cnt = Math.ceil (s.length/(ServerRND.length/2));
    var longrnd = "";
    for (var i = 0 ; i < cnt; i ++) longrnd = longrnd + ServerRND;

    var biUIDPIN = new BigInteger(getByteArray(s));
    longrnd = longrnd.substring (0,s.length*2);//one byte 2 hex digits
    var tmp = new BigInteger(longrnd,16);
    biUIDPIN = biUIDPIN.xor (tmp);
    var len = s.length.toString(16);
    if (s.length <= 0xF) len = "0"+len;
    var block1 = "0B"+ len + biUIDPIN.toString(16);

    //create static new password
    var s = UserIdValue + NEWPIN;
    var cnt = Math.ceil (s.length/(ServerRND.length/2));
    var longrnd = "";
    for (var i = 0 ; i < cnt; i ++) longrnd = longrnd + ServerRND;

    biUIDPIN = new BigInteger(getByteArray(s));
    longrnd = longrnd.substring (0,s.length*2);//one byte 2 hex digits
    tmp = new BigInteger(longrnd,16);
    biUIDPIN = biUIDPIN.xor (tmp);
    len = s.length.toString(16);
    if (s.length <= 0xF) len = "0"+len;
    block2 = "0C"+ len + biUIDPIN.toString(16);

    //create plain text
    var plaintext = new BigInteger (block1+block2, 16);

    var rsa = new RSAKey();
    rsa.setPublic(Modulus, Exponent);
    var rsablock = rsa.encrypt(plaintext);
    return rsablock.toString(16);
}

/**
 * Create an RSA block for the setRSAStatic_noVerify call in Client API.
 *
 * <p>
 * Uses RSA 1024 or 2048 for encryption and MD5 for hashing.
 * </p>
 *
 * @param {String}  UserIdValue          User identification for authentication.
 * @param {String}  PinValue        Password to be encrypted end-to-end.
 * @param {String}  ServerRND       Random to be XOR with password represented in hex string.
 *                                  If not in use, set to 16 zeros
 * @returns {String} RSA encrypted block represented in hex string.
 */
function encryptSetPwdNoVerifyRSABlock( UserIdValue,PinValue,ServerRND )
{
    //create static password hash without TLV
    var s = UserIdValue + PinValue;
    var biPwdHash = new BigInteger (MD5(s),16);//Big Integer password hash
    var tmp = new BigInteger(ServerRND,16);
    biPwdHash = biPwdHash.xor (tmp);
    var lengthB1 = Util.countBytes(biPwdHash.toString(16));
    var block1 = "02" + lengthB1 + biPwdHash.toString(16);


    //create plain text
    var plaintext = new BigInteger (block1, 16);
    var rsa = new RSAKey();
    rsa.setPublic(Modulus, Exponent);
    var rsablock = rsa.encrypt(plaintext);
    return rsablock;
}

/**
 * Create an RSA block for the setRSAStatic call in Client API.
 *
 * <p>
 * Uses RSA 1024 or 2048 for encryption and MD5 for hashing.
 * </p>
 *
 * @param {String}  UserIdValue     User identification for authentication.
 * @param {String}  PinValue        Password to be encrypted end-to-end.
 * @param {String}  OtipValue       OTP value to verify setting of password
 * @param {String}  ServerRND       Random to be XOR with password represented in hex string.
 *                                  If not in use, set to 16 zeros
 * @returns {String} RSA encrypted block represented in hex string.
 */
function encryptSetPwdRSABlock( UserIdValue,PinValue,OtipValue,ServerRND )
{
    //create static password hash without TLV
    var s = UserIdValue + PinValue;
    var biPwdHash = new BigInteger (MD5(s),16);//Big Integer password hash
    var tmp = new BigInteger(ServerRND,16);
    biPwdHash = biPwdHash.xor (tmp);
    var lengthB1 = Util.countBytes(biPwdHash.toString(16));
    var block1 = "02" + lengthB1 + biPwdHash.toString(16);


    //console.log("block1: "+block1);

    //create OTPW with TLV
    var OTIPLength = OtipValue.length.toString(16);
    if (OtipValue.length<16) OTIPLength = "0" + OTIPLength;
    var biOTIP = new BigInteger(getByteArray(OtipValue));
    var block2 = "03" + OTIPLength + biOTIP.toString(16);

    //console.log("block2: "+block2);


    //create plain text
    var plaintext = new BigInteger (block1+block2, 16);
    //console.log("Before encrypt: "+plaintext.toString(16));

    var rsa = new RSAKey();
    //alert(Modulus);
    rsa.setPublic(Modulus, Exponent);
    var rsablock = rsa.encrypt(plaintext);
    return rsablock;
}

/**
 * Create an RSA block for the changeRSAStatic call in Client API.
 *
 * <p>
 * Uses RSA 1024 or 2048 for encryption and MD5 for hashing.
 * </p>
 *
 * @param {String}  UserIdValue     User identification for authentication.
 * @param {String}  Pin1Value       Old password
 * @param {String}  Pin2Value       New password
 * @param {String}  OtipValue       OTP value to verify setting of password
 * @param {String}  ServerRND1      Random to be XOR with old password represented in hex string.
 *                                  If not in use, set to 16 zeros
 * @param {String}  ServerRND2      Random to be XOR with new password represented in hex string.
 *                                  If not in use, set to 16 zeros
 * @returns {String} RSA encrypted block represented in hex string.
 */
function encryptChangePwdRSABlock( UserIdValue,Pin1Value,Pin2Value,OtipValue,ServerRND1,ServerRND2) 
{
    //create static old password hash with TLV
    var s = UserIdValue + Pin1Value;
    var biPwdHash = new BigInteger (MD5(s),16);//Big Integer password hash
    var tmp = new BigInteger(ServerRND1,16);
    biPwdHash = biPwdHash.xor (tmp);
    var lengthB1 = Util.countBytes(biPwdHash.toString(16));
    var block1 = "01" + lengthB1 + biPwdHash.toString(16);

    //create static new password hash with TLV
    var s = UserIdValue + Pin2Value;
    var biPwdHash = new BigInteger (MD5(s),16);//Big Integer password hash
    var tmp = new BigInteger(ServerRND2,16);
    biPwdHash = biPwdHash.xor (tmp);
    var lengthB2 = Util.countBytes(biPwdHash.toString(16));
    var block2 = "02" + lengthB2 + biPwdHash.toString(16);



    //create OTPW with TLV
    var OTIPLength = OtipValue.length.toString(16);
    if (OtipValue.length<16) OTIPLength = "0" + OTIPLength;
    var biOTIP = new BigInteger(getByteArray(OtipValue));
    var block3 = "03" + OTIPLength + biOTIP.toString(16);

    //create plain text
    var plaintext = new BigInteger (block1+block2+block3, 16);

    var rsa = new RSAKey();
    rsa.setPublic(Modulus, Exponent);
    var rsablock = rsa.encrypt(plaintext);
    return rsablock;
}

/**
 * Create an RSA block for the changeRSAStatic_noVerify call in Client API.
 *
 * <p>
 * Uses RSA 1024 or 2048 for encryption and MD5 for hashing.
 * </p>
 *
 * @param {String}  UserIdValue     User identification for authentication.
 * @param {String}  Pin1Value       Old password
 * @param {String}  Pin2Value       New password
 * @param {String}  ServerRND1      Random to be XOR with old password represented in hex string.
 *                                  If not in use, set to 16 zeros
 * @param {String}  ServerRND2      Random to be XOR with new password represented in hex string.
 *                                  If not in use, set to 16 zeros
 * @returns {String} RSA encrypted block represented in hex string.
 */
function encryptChangePwdNoVerifyRSABlock( UserIdValue,Pin1Value,Pin2Value,ServerRND1,ServerRND2) 
{
    //create static old password hash with TLV
    var s = UserIdValue + Pin1Value;
    var biPwdHash = new BigInteger (MD5(s),16);//Big Integer password hash
    var tmp = new BigInteger(ServerRND1,16);
    biPwdHash = biPwdHash.xor (tmp);

    var lengthB1 = Util.countBytes(biPwdHash.toString(16));


    var block1 = "01" + lengthB1 + biPwdHash.toString(16);

    //create static new password hash with TLV
    var s = UserIdValue + Pin2Value;
    var biPwdHash = new BigInteger (MD5(s),16);//Big Integer password hash
    var tmp = new BigInteger(ServerRND2,16);
    biPwdHash = biPwdHash.xor (tmp);

    var lengthB2 = Util.countBytes(biPwdHash.toString(16));
    var block2 = "02" + lengthB2 + biPwdHash.toString(16);



    //create plain text
    var plaintext = new BigInteger (block1+block2, 16);

    var rsa = new RSAKey();
    rsa.setPublic(Modulus, Exponent);
    var rsablock = rsa.encrypt(plaintext);
    return rsablock;
}

/**
 * Create an RSA block for the verify2Factor call in Client API.
 *
 * <p>
 * Uses RSA 1024 or 2048 for encryption and MD5 for hashing.
 * </p>
 *
 * @param {String}  UserIdValue     User identification for authentication.
 * @param {String}  PinValue        Password to be encrypted end-to-end.
 * @param {String}  OtipValue       OTP value to verify setting of password
 * @param {String}  ServerRND       Random to be XOR with password represented in hex string.
 *                                  If not in use, set to 16 zeros
 * @returns {String} RSA encrypted block represented in hex string.
 */
function encryptVerifyRSABlock(UserIdValue, PinValue, OtipValue, ServerRND){
    //create static password hash without TLV
    var s = UserIdValue + PinValue;
    var biPwdHash = new BigInteger (MD5(s),16);//Big Integer password hash

    var tmp = new BigInteger(ServerRND,16);
    biPwdHash = biPwdHash.xor (tmp);

    //create OTPW with TLV
    var OTIPLength = OtipValue.length.toString(16);
    if (OtipValue.length<16) OTIPLength = "0" + OTIPLength;
    var biOTIP = new BigInteger(getByteArray(OtipValue));
    var TLVOTIP = "03" + OTIPLength + biOTIP.toString(16);
    biTLVOTIP = new BigInteger(TLVOTIP,16);

    //create plain text
    tmp = biPwdHash.toString(16) + biTLVOTIP.toString(16);
    var biPwdHashLength = Util.countBytes(biPwdHash.toString(16));
    var plaintext = new BigInteger
    ("01" + biPwdHashLength +  tmp , 16);

    var rsa = new RSAKey();
    rsa.setPublic(Modulus, Exponent);
    var rsablock = rsa.encrypt(plaintext);
    return rsablock;
}
/**
 * @private
 */
function getUserIDHexString(useridStr)
{
    var useridByte = getByteArray(useridStr);
    userIDHexString = "";
    for (var i = 0 ; i < useridByte.length; i++){
        var num = "";
        if ( useridByte[i] <= 0xF) num = "0"+useridByte[i].toString(16);
        else num = useridByte[i].toString(16);
        userIDHexString = userIDHexString + num;
    }
    return userIDHexString + "00";
}
/**
 * Create an RSA block for the verifyRSAOTIP2 call in Client API.
 *
 * <p>
 * Uses RSA 1024 or 2048 for encryption and MD5 for hashing.
 * </p>
 *
 * @param {String}  UserIdValue     User identification for authentication.
 * @param {String}  OtipValue 		OTP value to verify setting of password
 * @param {String}  ServerRND      Random to be XOR with password represented in hex string.
 *                                  If not in use, set to 16 zeros
 * @returns {String} RSA encrypted block represented in hex string.
 */

function encryptVerify2RSABlock(UserIdValue, OtipValue, ServerRND){
    //creating first block
    //0x03 || (length of OTIP) || (ServerRND[0-2*length of OTIP] ^ OTIP byte array)
    //get sub random
    var subRND = ServerRND.substring(0,OtipValue.length*2);
    var biSubRND = new BigInteger(subRND,16);

    //create first block
    var OTIPLength = OtipValue.length.toString(16);
    if (OtipValue.length<16) OTIPLength = "0" + OTIPLength;
    var biOTIP = new BigInteger(getByteArray(OtipValue));
    var TLVOTIP = "03" + OTIPLength + (biOTIP.xor(biSubRND)).toString(16);
    biTLVOTIP = new BigInteger(TLVOTIP,16);

    //create static password hash without TLV
    var s = UserIdValue + OtipValue;
    var biUID_OTIP_Hash = new BigInteger (MD5(s),16);//Big Integer password hash
    var tmp = new BigInteger(ServerRND,16);
    biUID_OTIP_Hash = biUID_OTIP_Hash.xor (tmp);

    var biUID_OTIP_Hash_Length = Util.countBytes(biUID_OTIP_Hash.toString(16));
    //create plain text
    tmp = biTLVOTIP.toString(16) + "02" + biUID_OTIP_Hash_Length + biUID_OTIP_Hash.toString(16);
    var plaintext = new BigInteger( tmp , 16);

    var rsa = new RSAKey();
    rsa.setPublic(Modulus, Exponent);
    var rsablock = rsa.encrypt(plaintext);
    return rsablock;
}
/**
 * Create an RSA block for the verifyRSAOTIPToken call in Client API.
 *
 * <p>
 * Uses RSA 1024 or 2048 for encryption.
 * </p>
 * @param {String}  OtipValue 		OTP value to verify setting of password
 * @returns {String} RSA encrypted block represented in hex string.
 */
function encryptVerifyOtipRSABlock(OtipValue) {
    //0x03 || (length of OTIP) || (OTIP byte array)
    //create first block

    var OTIPLength = OtipValue.length.toString(16);
    if (OtipValue.length<16) OTIPLength = "0" + OTIPLength;
    var biOTIP = new BigInteger(getByteArray(OtipValue));
    var TLVOTIP = "03" + OTIPLength + biOTIP.toString(16);
    biTLVOTIP = new BigInteger(TLVOTIP,16);

    //encrypt

    var rsa = new RSAKey();
    rsa.setPublic(Modulus, Exponent);
    var rsablock = rsa.encrypt(biTLVOTIP);
    return rsablock;
}

/**
 * Create an RSA block for the verifyRSAStatic call in Client API.
 *
 * <p>
 * Uses RSA 1024 or 2048 for encryption and MD5 for hashing.
 * </p>
 *
 * @param {String}  UserIdValue     User identification for authentication.
 * @param {String}  PinValue        Password to be encrypted end-to-end.
 * @param {String}  ServerRND       Random to be XOR with password represented in hex string.
 *                                  If not in use, set to 16 zeros
 * @returns {String} RSA encrypted block represented in hex string.
 */
function encryptVerifyStaticRSABlock( UserIdValue, PinValue, ServerRND){
    //create static password hash without TLV
    var s = UserIdValue + PinValue;
    var hashvalue = MD5(s);

    var biPwdHash = new BigInteger (hashvalue,16);//Big Integer password hash
    var tmp = new BigInteger(ServerRND,16);
    biPwdHash = biPwdHash.xor (tmp);

    //create plain text
    var plaintext = new BigInteger("0110" +  biPwdHash.toString(16), 16);

    //console.log('plaintext: '+plaintext.toString(16));

    var rsa = new RSAKey();
    rsa.setPublic(Modulus, Exponent);
    var rsablock = rsa.encrypt(plaintext);

    return rsablock;
}

/**
 * Algorithm:   RSA encryption 1024/MD5
 * Return RSA encrypted Vasco Challenge OTP
 *
 * @param {String}  OtpValue		OTP value to verify
 * @param {String}  challenge		Random to be XOR with OTP in hex string.
 *
 * @returns {String} RSA encrypted block represented in hex string.
 */
function encryptVascoResponse(OtpValue, Challenge){

	  // MD5 challenge if not equal to 16
	  var hashvalue = Challenge;
	  if(Challenge.length != 16)  hashvalue = MD5(Challenge);
	  //console.log("hashvalue: "+hashvalue);

	  hashvalue = hashvalue.substring(0, OtpValue.length*2);

	  //console.log("hashvalue: "+hashvalue);
	  //console.log("OtpValue: "+OtpValue);

	  // XOR OTP against hash value
	  var biOTPHash = new BigInteger (getByteArray(OtpValue));
	  var tmp = new BigInteger(hashvalue,16);
	  biOTPHash = biOTPHash.xor (tmp);

	  //console.log("tmp: " + biOTPHash.toString(16));

	  // Process length
	  var OTIPLength = OtpValue.length.toString(16);
	  if (OtpValue.length<16) OTIPLength = "0" + OTIPLength;

	  // Form TLV
	  var plaintext = new BigInteger("03" + OTIPLength + biOTPHash.toString(16) , 16);

	  // RSA encrypt block
	  var rsa = new RSAKey();
	  rsa.setPublic(Modulus, Exponent);
	  var rsablock = rsa.encrypt(plaintext);
	  return rsablock;
}


/**
 * @private
 */
function encryptVerifyISOBlock(pinStr){

    function formatPIN(PINval, PadLen){
	var pad = new Array();
	var i, h, l;
	for (i=0; i<PadLen ;i++ ){ pad[i]=0xff; }
	for (i=0;i<PINval.length && i<9 ; i++ ){
	    var dec = PINval.charCodeAt(i);
	    h=dec % 16;
	    if (i%2 == 0){ pad[i/2]=( pad[i/2] & (h * 16 + 0x0f));
	    }else{
                var j = Math.floor(i/2);
		pad[j]=(pad[j] & (h | 0xf0));
            }
	}
	return pad;
    }

   /*
     function formatPIN(PINval, PadLen){
      var pad = new Array();
      for (i=0; i<PadLen; i++){ pad[i]=0xff; }
      for(i=0; i<PINval.length; i++){
          var h;
          if( PINval[i] >= '0' && PINval[i] <= '9' ){
              h = (PINval.charCodeAt(i)%16)&0x0F;
          }else{
              h = (((PINval.charCodeAt(i)-65+1)&0x0F)+9);
          }
          var j= Math.floor(i/2);
          if (i%2 == 0){ pad[j]=pad[j]&(h<<4);}
          else{
              pad[j]= pad[j] | h;
          }
      }
      return pad;
  }
   */
    function formVerifyISOBlock(pin){
        var firstBlock = "0608";
        if (pin.length <= 9){
          firstBlock+="0"+pin.length;
        }else{ firstBlock+=pin.length; }
        firstBlock+=Util.toHexString(formatPIN(pin, 7));
        return firstBlock;
    }

    var isoBlock = new BigInteger(formVerifyISOBlock(pinStr),16)
    var rsa = new RSAKey();
    rsa.setPublic(Modulus, Exponent );
    var rsablock = rsa.encrypt(isoBlock).toString(16);
    return rsablock;
}

/**
 * @private
 */
function support32bitComputation(){
    var a = 0x12345678;
    var b = 0xABCDEF98;
    var c = a+b;
    if(c == 3187820048) return true;
    else return false;
}
