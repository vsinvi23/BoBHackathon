/*!
 *
 * @description DSSS JavaScript End-to-End Encryption Package(SHA256)
 * @version 1.6.3 (15 December 2018)
 * @author Gemalto, http://www.gemalto.com
 */

/**
* <p>DSSS JavaScript End-to-End Encryption Package(SHA256)<br>
* This package contains open source libraries or binaries within its distribution package.
* For more information, please see respectively included license.</p>
* <p>
* Package:<br>
* <ul
* <li>DSSSCryptography256.js</li>
* <li>jsbn.js</li>
* <li>des.js</li>
* <li>rsa.js</li>
* <li>sha256.js</li>
* <li>Util.js</li>
* </ul>
* </p>
*/

/**
 * Create an RSA block for the setRSAStatic_noVerify call in Client API.
 *
 * <p>
 * Uses RSA 1024 or 2048 for encryption and SHA-256 for hashing.
 * </p>
 *
 * <p>
 * Even though this method uses SHA-256 hash the end result will be
 * folded/compressed when sent to the server and will only be 16 bytes.
 * Consider using {@link encryptSetPwdNoVerifyRSABlock256_32} for a full SHA-256
 * hash.
 * </p>
 *
 * @param {String}  exponentHexStr  RSA public key exponent represented in hex string.
 * @param {String}  modulusHexStr   RSA public key modulus represented in hex string.
 * @param {String}  UserIdValue          User identification for authentication.
 * @param {String}  PinValue        Password to be encrypted end-to-end.
 * @param {String}  ServerRND       Random to be XOR with password represented in hex string.
 *                                  If not in use, set to 16 zeros
 * @returns {String} RSA encrypted block represented in hex string.
 */
function encryptSetPwdNoVerifyRSABlock256(exponentHexStr, modulusHexStr, UserIdValue,PinValue,ServerRND)
{
   return __encryptSetPwdNoVerifyRSABlock256(exponentHexStr, modulusHexStr, UserIdValue,PinValue,ServerRND);
}

/**
 * Create an RSA block for the setRSAStatic_noVerify call in Client API.
 *
 * <p>
 * Uses RSA 1024 or 2048 for encryption and SHA-256 for hashing.
 * </p>
 *
 * <p>
 * This method uses the full SHA-256 hash as compared to
 * {@link encryptSetPwdNoVerifyRSABlock256}.
 * </p>
 *
 * @param {String}  exponentHexStr  RSA public key exponent represented in hex string.
 * @param {String}  modulusHexStr   RSA public key modulus represented in hex string.
 * @param {String}  UserIdValue          User identification for authentication.
 * @param {String}  PinValue        Password to be encrypted end-to-end.
 * @param {String}  ServerRND       Random to be XOR with password represented in hex string.
 *                                  If not in use, set to 16 zeros
 * @returns {String} RSA encrypted block represented in hex string.
 */
function encryptSetPwdNoVerifyRSABlock256_32(exponentHexStr, modulusHexStr, UserIdValue,PinValue,ServerRND)
{
   return __encryptSetPwdNoVerifyRSABlock256(exponentHexStr, modulusHexStr, UserIdValue,PinValue,ServerRND,0);
}

function __encryptSetPwdNoVerifyRSABlock256(exponentHexStr, modulusHexStr, UserIdValue,PinValue,ServerRND,foldFlag)
{
    "exponentHexStr:nomunge, modulusHexStr:nomunge, UserIdValue:nomunge, PinValue:nomunge, ServerRND:nomunge";

    //create static password hash without TLV
    var s = UserIdValue + PinValue;
    var pwdHashBytes = doSHA256Hash(Util.getByteArray(s));
    var pwdBytes;
    if(!((arguments.length >=6) &&(foldFlag == 0)))
    {
        pwdBytes = Util.foldSHA256To16Bytes(pwdHashBytes);
    }
    else
    {
        pwdBytes = pwdHashBytes;
    }

    var biPwdHash = new BigInteger(Util.toHexString(pwdBytes), 16);//Big Integer pas
    var tmp = new BigInteger(ServerRND,16);

    biPwdHash = biPwdHash.xor (tmp);
    var biPwdHashLength = Util.countBytes(biPwdHash.toString(16));
    var block1 = "02" + biPwdHashLength + biPwdHash.toString(16);

    //create plain text
    var plaintext = new BigInteger (block1, 16);
    var rsa = new RSAKey();
    rsa.setPublic(modulusHexStr, exponentHexStr);
    var rsablock = rsa.encrypt(plaintext).toString(16);
    return rsablock;
}

/**
 * Create an RSA block for the verifyRSAStatic call in Client API.
 *
 * <p>
 * Uses RSA 1024 or 2048 for encryption and SHA-256 for hashing.
 * </p>
 *
 * <p>
 * Even though this method uses SHA-256 hash the end result will be
 * folded/compressed when sent to the server and will only be 16 bytes.
 * Consider using {@link encryptVerifyStaticRSABlock256_32} for a full SHA-256
 * hash.
 * </p>
 *
 * @param {String}  exponentHexStr  RSA public key exponent represented in hex string.
 * @param {String}  modulusHexStr   RSA public key modulus represented in hex string.
 * @param {String}  UserIdValue          User identification for authentication.
 * @param {String}  PinValue        Password to be encrypted end-to-end.
 * @param {String}  ServerRND       Random to be XOR with password represented in hex string.
 *                                  If not in use, set to 16 zeros
 * @returns {String} RSA encrypted block represented in hex string.
 */
function encryptVerifyStaticRSABlock256(exponentHexStr, modulusHexStr, UserIdValue, PinValue, ServerRND)
{
    return __encryptVerifyStaticRSABlock256(exponentHexStr, modulusHexStr, UserIdValue, PinValue, ServerRND);
}

/**
 * Create an RSA block for the verifyRSAStatic call in Client API.
 *
 * <p>
 * Uses RSA 1024 or 2048 for encryption and SHA-256 for hashing.
 * </p>
 *
 * <p>
 * This method uses the full SHA-256 hash as compared to
 * {@link encryptVerifyStaticRSABlock256}.
 * </p>
 *
 * @param {String}  exponentHexStr  RSA public key exponent represented in hex string.
 * @param {String}  modulusHexStr   RSA public key modulus represented in hex string.
 * @param {String}  UserIdValue          User identification for authentication.
 * @param {String}  PinValue        Password to be encrypted end-to-end.
 * @param {String}  ServerRND       Random to be XOR with password represented in hex string.
 *                                  If not in use, set to 16 zeros
 * @returns {String} RSA encrypted block represented in hex string.
 */
function encryptVerifyStaticRSABlock256_32(exponentHexStr, modulusHexStr, UserIdValue, PinValue, ServerRND)
{
    return __encryptVerifyStaticRSABlock256(exponentHexStr, modulusHexStr, UserIdValue, PinValue, ServerRND,0);
}

function __encryptVerifyStaticRSABlock256(exponentHexStr, modulusHexStr, UserIdValue, PinValue, ServerRND,foldFlag)
{

    "exponentHexStr:nomunge, modulusHexStr:nomunge, UserIdValue:nomunge, PinValue:nomunge, ServerRND:nomunge";
    //create static password hash without TLV
   var s = UserIdValue + PinValue;
   var pwdHashBytes =  doSHA256Hash(Util.getByteArray(s));
   var pwdBytes;
    if(!((arguments.length >=6) &&(foldFlag == 0)))
    {
        pwdBytes = Util.foldSHA256To16Bytes(pwdHashBytes);
    }
    else
    {
        pwdBytes = pwdHashBytes;
    }

   var biPwdHash = new BigInteger(Util.toHexString(pwdBytes), 16);//Big Integer pas
   var tmp = new BigInteger(ServerRND,16);
   biPwdHash = biPwdHash.xor (tmp);
   var biPwdHashLength = Util.countBytes(biPwdHash.toString(16));
   //create plain text
   var plaintext = new BigInteger
   ("01" + biPwdHashLength +  biPwdHash.toString(16)  , 16);
   var rsa = new RSAKey();
   rsa.setPublic(modulusHexStr, exponentHexStr );
   var rsablock = rsa.encrypt(plaintext).toString(16);
   return rsablock;
}

/**
 * Create an RSA block for the setRSAStatic call in Client API.
 *
 * <p>
 * Uses RSA 1024 or 2048 for encryption and SHA-256 for hashing.
 * </p>
 *
 * <p>
 * Even though this method uses SHA-256 hash the end result will be
 * folded/compressed when sent to the server and will only be 16 bytes.
 * Consider using {@link encryptSetPwdRSABlock256_32} for a full SHA-256
 * hash.
 * </p>
 *
 * @param {String}  exponentHexStr  RSA public key exponent represented in hex string.
 * @param {String}  modulusHexStr   RSA public key modulus represented in hex string.
 * @param {String}  UserIdValue     User identification for authentication.
 * @param {String}  PinValue        Password to be encrypted end-to-end.
 * @param {String}  OtipValue       OTP value to verify setting of password
 * @param {String}  ServerRND       Random to be XOR with password represented in hex string.
 *                                  If not in use, set to 16 zeros
 * @returns {String} RSA encrypted block represented in hex string.
 */
function encryptSetPwdRSABlock256(exponentHexStr, modulusHexStr, UserIdValue,PinValue,OtipValue,ServerRND)
{
    return __encryptSetPwdRSABlock256(exponentHexStr, modulusHexStr, UserIdValue,PinValue,OtipValue,ServerRND);
}

/**
 * Create an RSA block for the setRSAStatic call in Client API.
 *
 * <p>
 * Uses RSA 1024 or 2048 for encryption and SHA-256 for hashing.
 * </p>
 *
 * <p>
 * This method uses the full SHA-256 hash as compared to
 * {@link encryptSetPwdRSABlock256}.
 * </p>
 *
 * @param {String}  exponentHexStr  RSA public key exponent represented in hex string.
 * @param {String}  modulusHexStr   RSA public key modulus represented in hex string.
 * @param {String}  UserIdValue     User identification for authentication.
 * @param {String}  PinValue        Password to be encrypted end-to-end.
 * @param {String}  OtipValue       OTP value to verify setting of password
 * @param {String}  ServerRND       Random to be XOR with password represented in hex string.
 *                                  If not in use, set to 16 zeros
 * @returns {String} RSA encrypted block represented in hex string.
 */
function encryptSetPwdRSABlock256_32(exponentHexStr, modulusHexStr, UserIdValue,PinValue,OtipValue,ServerRND)
{
    return __encryptSetPwdRSABlock256(exponentHexStr, modulusHexStr, UserIdValue,PinValue,OtipValue,ServerRND,0);
}

function __encryptSetPwdRSABlock256(exponentHexStr, modulusHexStr, UserIdValue,PinValue,OtipValue,ServerRND,foldFlag)
{
	 "exponentHexStr:nomunge, modulusHexStr:nomunge, UserIdValue:nomunge, PinValue:nomunge, OtipValue:nomunge, ServerRND:nomunge";

    //create static password hash without TLV
    var s = UserIdValue + PinValue;
    var pwdHashBytes =  doSHA256Hash(Util.getByteArray(s));
    var pwdBytes;
    if(!((arguments.length >=6) &&(foldFlag == 0)))
    {
        pwdBytes = Util.foldSHA256To16Bytes(pwdHashBytes);
    }
    else
    {
        pwdBytes = pwdHashBytes;
    }

    var biPwdHash = new BigInteger(Util.toHexString(pwdBytes), 16);//Big Integer pas
    var tmp = new BigInteger(ServerRND,16);
    biPwdHash = biPwdHash.xor (tmp);

    var biPwdHashLength = Util.countBytes(biPwdHash.toString(16));
    var block1 = "02" + biPwdHashLength + biPwdHash.toString(16);

    //create OTPW with TLV
    var OTIPLength = OtipValue.length.toString(16);
    if (OtipValue.length<16) OTIPLength = "0" + OTIPLength;
    var biOTIP = new BigInteger(getByteArray(OtipValue));
    var block2 = "03" + OTIPLength + biOTIP.toString(16);

    //create plain text
    var plaintext = new BigInteger (block1+block2, 16);
    var rsa = new RSAKey();
    //alert(Modulus);
    rsa.setPublic(modulusHexStr, exponentHexStr);
    var rsablock = rsa.encrypt(plaintext);
    return rsablock.toString(16);
}

/**
 * Create an RSA block for the verify2Factor call in Client API.
 *
 * <p>
 * Uses RSA 1024 or 2048 for encryption and SHA-256 for hashing.
 * </p>
 *
 * <p>
 * Even though this method uses SHA-256 hash the end result will be
 * folded/compressed when sent to the server and will only be 16 bytes.
 * Consider using {@link encryptVerifyRSABlock256_32} for a full SHA-256
 * hash.
 * </p>
 *
 * @param {String}  exponentHexStr  RSA public key exponent represented in hex string.
 * @param {String}  modulusHexStr   RSA public key modulus represented in hex string.
 * @param {String}  UserIdValue     User identification for authentication.
 * @param {String}  PinValue        Password to be encrypted end-to-end.
 * @param {String}  OtipValue       OTP value to verify setting of password
 * @param {String}  ServerRND       Random to be XOR with password represented in hex string.
 *                                  If not in use, set to 16 zeros
 * @returns {String} RSA encrypted block represented in hex string.
 */
function encryptVerifyRSABlock256(exponentHexStr, modulusHexStr, UserIdValue, PinValue, OtipValue, ServerRND)
{
    return __encryptVerifyRSABlock256(exponentHexStr, modulusHexStr, UserIdValue, PinValue, OtipValue, ServerRND);
}

/**
 * Create an RSA block for the verify2Factor call in Client API.
 *
 * <p>
 * Uses RSA 1024 or 2048 for encryption and SHA-256 for hashing.
 * </p>
 *
 * <p>
 * This method uses the full SHA-256 hash as compared to
 * {@link encryptVerifyRSABlock256}.
 * </p>
 *
 * @param {String}  exponentHexStr  RSA public key exponent represented in hex string.
 * @param {String}  modulusHexStr   RSA public key modulus represented in hex string.
 * @param {String}  UserIdValue     User identification for authentication.
 * @param {String}  PinValue        Password to be encrypted end-to-end.
 * @param {String}  OtipValue       OTP value to verify setting of password
 * @param {String}  ServerRND       Random to be XOR with password represented in hex string.
 *                                  If not in use, set to 16 zeros
 * @returns {String} RSA encrypted block represented in hex string.
 */
function encryptVerifyRSABlock256_32(exponentHexStr, modulusHexStr, UserIdValue, PinValue, OtipValue, ServerRND)
{
    return __encryptVerifyRSABlock256(exponentHexStr, modulusHexStr, UserIdValue, PinValue, OtipValue, ServerRND,0);
}

function __encryptVerifyRSABlock256(exponentHexStr, modulusHexStr, UserIdValue, PinValue, OtipValue, ServerRND,foldFlag)
{

	"exponentHexStr:nomunge, modulusHexStr:nomunge, UserIdValue:nomunge, PinValue:nomunge, OtipValue:nomunge, ServerRND:nomunge";

    //create static password hash without TLV
    var s = UserIdValue + PinValue;
    var pwdHashBytes =  doSHA256Hash(Util.getByteArray(s));
    var pwdBytes;
    if(!((arguments.length >=6) &&(foldFlag == 0)))
    {
        pwdBytes = Util.foldSHA256To16Bytes(pwdHashBytes);
    }
    else
    {
        pwdBytes = pwdHashBytes;
    }
    /*
    var pwdBytes = new Array(16);
    for(var i=0; i<16; i++){
        pwdBytes[i] = pwdHashBytes[i] ^ pwdHashBytes[i+16];
    }
    */
    var biPwdHash = new BigInteger(Util.toHexString(pwdBytes), 16);//Big Integer pas

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
    rsa.setPublic(modulusHexStr, exponentHexStr);
    var rsablock = rsa.encrypt(plaintext);
    return rsablock.toString(16);
}

/**
 * Create an RSA block for the changeRSAStatic_noVerify call in Client API.
 *
 * <p>
 * Uses RSA 1024 or 2048 for encryption and SHA-256 for hashing.
 * </p>
 *
 * <p>
 * Even though this method uses SHA-256 hash the end result will be
 * folded/compressed when sent to the server and will only be 16 bytes.
 * Consider using {@link encryptChangePwdNoVerifyRSABlock256_32} for a full
 * SHA-256 hash.
 * </p>
 *
 * @param {String}  exponentHexStr  RSA public key exponent represented in hex string.
 * @param {String}  modulusHexStr   RSA public key modulus represented in hex string.
 * @param {String}  UserIdValue     User identification for authentication.
 * @param {String}  Pin1Value       Old password
 * @param {String}  Pin2Value       New password
 * @param {String}  ServerRND1      Random to be XOR with old password represented in hex string.
 *                                  If not in use, set to 16 zeros
 * @param {String}  ServerRND2      Random to be XOR with new password represented in hex string.
 *                                  If not in use, set to 16 zeros
 * @returns {String} RSA encrypted block represented in hex string.
 */
function encryptChangePwdNoVerifyRSABlock256(exponentHexStr, modulusHexStr, UserIdValue,Pin1Value,Pin2Value,ServerRND1,ServerRND2)
{
    return __encryptChangePwdNoVerifyRSABlock256(exponentHexStr, modulusHexStr, UserIdValue,Pin1Value,Pin2Value,ServerRND1,ServerRND2);
}

/**
 * Create an RSA block for the changeRSAStatic_noVerify call in Client API.
 *
 * <p>
 * Uses RSA 1024 or 2048 for encryption and SHA-256 for hashing.
 * </p>
 *
 * <p>
 * This method uses the full SHA-256 hash as compared to
 * {@link encryptChangePwdNoVerifyRSABlock256}.
 * </p>
 *
 * @param {String}  exponentHexStr  RSA public key exponent represented in hex string.
 * @param {String}  modulusHexStr   RSA public key modulus represented in hex string.
 * @param {String}  UserIdValue     User identification for authentication.
 * @param {String}  Pin1Value       Old password
 * @param {String}  Pin2Value       New password
 * @param {String}  ServerRND1      Random to be XOR with old password represented in hex string.
 *                                  If not in use, set to 16 zeros
 * @param {String}  ServerRND2      Random to be XOR with new password represented in hex string.
 *                                  If not in use, set to 16 zeros
 * @returns {String} RSA encrypted block represented in hex string.
 */
function encryptChangePwdNoVerifyRSABlock256_32(exponentHexStr, modulusHexStr, UserIdValue,Pin1Value,Pin2Value,ServerRND1,ServerRND2)
{
    return __encryptChangePwdNoVerifyRSABlock256(exponentHexStr, modulusHexStr, UserIdValue,Pin1Value,Pin2Value,ServerRND1,ServerRND2,0);
}

function __encryptChangePwdNoVerifyRSABlock256(exponentHexStr, modulusHexStr, UserIdValue,Pin1Value,Pin2Value,ServerRND1,ServerRND2,foldFlag)
{
	"exponentHexStr:nomunge, modulusHexStr:nomunge, UserIdValue:nomunge, Pin1Value:nomunge, Pin2Value:nomunge, ServerRND1:nomunge, ServerRND2:nomunge";

    //create static old password hash with TLV

    //create static password hash without TLV
    var s = UserIdValue + Pin1Value;
    var pwdHashBytes =  doSHA256Hash(Util.getByteArray(s));
    var pwdBytes;
    if(!((arguments.length >=6) &&(foldFlag == 0)))
    {
        pwdBytes = Util.foldSHA256To16Bytes(pwdHashBytes);
    }
    else
    {
        pwdBytes = pwdHashBytes;
    }

    var biPwdHash = new BigInteger(Util.toHexString(pwdBytes), 16);//Big Integer pas
    var tmp = new BigInteger(ServerRND1,16);
    biPwdHash = biPwdHash.xor (tmp);

    var biPwdHashLength = Util.countBytes(biPwdHash.toString(16));
    var block1 = "01" + biPwdHashLength + biPwdHash.toString(16);

    //create static new password hash with TLV
    var s = UserIdValue + Pin2Value;
    var pwdHashBytes =  doSHA256Hash(Util.getByteArray(s));
    var pwdBytes = new Array(16);
    for(var i=0; i<16; i++){
        pwdBytes[i] = pwdHashBytes[i] ^ pwdHashBytes[i+16];
    }
    var biPwdHash = new BigInteger(Util.toHexString(pwdBytes), 16);//Big Integer pas
    var tmp = new BigInteger(ServerRND2,16);
    biPwdHash = biPwdHash.xor (tmp);

    var biPwdHashLength = Util.countBytes(biPwdHash.toString(16));
    var block2 = "02" + biPwdHashLength + biPwdHash.toString(16);


    //create plain text
    var plaintext = new BigInteger (block1+block2, 16);

    var rsa = new RSAKey();
    rsa.setPublic(modulusHexStr, exponentHexStr);
    var rsablock = rsa.encrypt(plaintext);
    return rsablock.toString(16);
}

/**
 * Create an RSA block for the changeRSAStatic call in Client API.
 *
 * <p>
 * Uses RSA 1024 or 2048 for encryption and SHA-256 for hashing.
 * </p>
 *
 * <p>
 * Even though this method uses SHA-256 hash the end result will be
 * folded/compressed when sent to the server and will only be 16 bytes.
 * Consider using {@link encryptChangePwdRSABlock256_32} for a full SHA-256
 * hash.
 * </p>
 *
 * @param {String}  exponentHexStr  RSA public key exponent represented in hex string.
 * @param {String}  modulusHexStr   RSA public key modulus represented in hex string.
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
function encryptChangePwdRSABlock256(exponentHexStr, modulusHexStr, UserIdValue,Pin1Value,Pin2Value,OtipValue,ServerRND1,ServerRND2)
{
    return __encryptChangePwdRSABlock256(exponentHexStr, modulusHexStr, UserIdValue,Pin1Value,Pin2Value,OtipValue,ServerRND1,ServerRND2);
}

/**
 * Create an RSA block for the changeRSAStatic call in Client API.
 *
 * <p>
 * Uses RSA 1024 or 2048 for encryption and SHA-256 for hashing.
 * </p>
 *
 * <p>
 * This method uses the full SHA-256 hash as compared to
 * {@link encryptChangePwdRSABlock256}.
 * </p>
 *
 * @param {String}  exponentHexStr  RSA public key exponent represented in hex string.
 * @param {String}  modulusHexStr   RSA public key modulus represented in hex string.
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
function encryptChangePwdRSABlock256_32(exponentHexStr, modulusHexStr, UserIdValue,Pin1Value,Pin2Value,OtipValue,ServerRND1,ServerRND2)
{
    return __encryptChangePwdRSABlock256(exponentHexStr, modulusHexStr, UserIdValue,Pin1Value,Pin2Value,OtipValue,ServerRND1,ServerRND2,0);
}

function __encryptChangePwdRSABlock256(exponentHexStr, modulusHexStr, UserIdValue,Pin1Value,Pin2Value,OtipValue,ServerRND1,ServerRND2,foldFlag)
{
	"exponentHexStr:nomunge, modulusHexStr:nomunge, UserIdValue:nomunge, Pin1Value:nomunge, Pin2Value:nomunge, OtipValue:nomunge, ServerRND1:nomunge, ServerRND2:nomunge";

    //create static old password hash with TLV
    var s = UserIdValue + Pin1Value;
    var pwdHashBytes =  doSHA256Hash(Util.getByteArray(s));
    var pwdBytes;
    if(!((arguments.length >=6) &&(foldFlag == 0)))
    {
        pwdBytes = Util.foldSHA256To16Bytes(pwdHashBytes);
    }
    else
    {
        pwdBytes = pwdHashBytes;
    }

    var biPwdHash = new BigInteger(Util.toHexString(pwdBytes), 16);//Big Integer pas
    var tmp = new BigInteger(ServerRND1,16);
    biPwdHash = biPwdHash.xor (tmp);

    var biPwdHashLength = Util.countBytes(biPwdHash.toString(16));
    var block1 = "01" + biPwdHashLength + biPwdHash.toString(16);

   //create static new password hash with TLV
    var s = UserIdValue + Pin2Value;
    var pwdHashBytes =  doSHA256Hash(Util.getByteArray(s));
    var pwdBytes;
    if(!((arguments.length >=6) &&(foldFlag == 0)))
    {
        pwdBytes = Util.foldSHA256To16Bytes(pwdHashBytes);
    }
    else
    {
        pwdBytes = pwdHashBytes;
    }

    var biPwdHash = new BigInteger(Util.toHexString(pwdBytes), 16);//Big Integer pas
    var tmp = new BigInteger(ServerRND2,16);
    biPwdHash = biPwdHash.xor (tmp);

    var biPwdHashLength = Util.countBytes(biPwdHash.toString(16));
    var block2 = "02" + biPwdHashLength + biPwdHash.toString(16);

    //create OTPW with TLV
    var OTIPLength = OtipValue.length.toString(16);
    if (OtipValue.length<16) OTIPLength = "0" + OTIPLength;
    var biOTIP = new BigInteger(getByteArray(OtipValue));
    var block3 = "03" + OTIPLength + biOTIP.toString(16);

    //create plain text
    var plaintext = new BigInteger (block1+block2+block3, 16);

    var rsa = new RSAKey();
    rsa.setPublic(modulusHexStr, exponentHexStr);
    var rsablock = rsa.encrypt(plaintext);
    return rsablock.toString(16);
}

/**
 * Return RSA encrypted block for end-to-end verification of OTP.
 * @param {String}  exponentHexStr  RSA public key exponent represented in hex string.
 * @param {String}  modulusHexStr   RSA public key modulus represented in hex string.
 * @param {String}  OtipValue       OTP value to verify setting of password
 */
function encryptVerifyOtipRSABlock256(exponentHexStr, modulusHexStr, OtipValue) {

	"exponentHexStr:nomunge, modulusHexStr:nomunge, OtipValue:nomunge";

    //0x03 || (length of OTIP) || (OTIP byte array)
    //create first block

    var OTIPLength = OtipValue.length.toString(16);
    if (OtipValue.length<16) OTIPLength = "0" + OTIPLength;
    var biOTIP = new BigInteger(getByteArray(OtipValue));
    var TLVOTIP = "03" + OTIPLength + biOTIP.toString(16);
    biTLVOTIP = new BigInteger(TLVOTIP,16);

    //encrypt

    var rsa = new RSAKey();
    rsa.setPublic(modulusHexStr, exponentHexStr);
    var rsablock = rsa.encrypt(biTLVOTIP);
    return rsablock.toString(16);
}

/**
 * Return RSA encrypted Vasco Challenge OTP
 *
 * @param {String}  exponentHexStr  RSA public key exponent represented in hex string.
 * @param {String}  modulusHexStr   RSA public key modulus represented in hex string.
 * @param {String}  OtpValue		OTP value to verify
 * @param {String}  Challenge		Random to be XOR with OTP in hex string.
 *
 * @returns {String} RSA encrypted block represented in hex string.
 */
function encryptVascoResponse4Params(exponentHexStr, modulusHexStr, OtpValue, Challenge){

	"exponentHexStr:nomunge, modulusHexStr:nomunge, OtpValue:nomunge, Challenge:nomunge";

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
	  rsa.setPublic(modulusHexStr, exponentHexStr);
	  var rsablock = rsa.encrypt(plaintext);
	  return rsablock;
}


/**
 * @private
 */
function doSHA256Hash(inputMsgByteArray){

	"inputMsgByteArray:nomunge";

    return Util.fromHexString(sha256Hash(Util.cByteArrayToNString(inputMsgByteArray)));
}

/**
 * Algorithm:   RSA encryption 1024(Triple DES key)
 *              Triple DES encryption (Data)
 * Mode:        Triple DES CBC Mode
 * Padding:     PKCS1 (RSA)
 *              PKCS5Padding (Triple DES)
 * @param {String}  exponentHexStr    RSA public key exponent represented in hex string.
 * @param {String}  modulusHexStr     RSA public key modulus represented in hex string.
 * @param {String}  dataStr           Data string.
 * @param {String}  ivHex             Initialization vector of 8 bytes represented in hex string.
 * @returns {String}  Encrypted block represented in hex string.
 */
function rsaDES3EncryptDataPKCS5Padding_CBC(exponentHexStr, modulusHexStr, dataStr, ivHex)
{
    "exponentHexStr:nomunge, modulusHexStr:nomunge, dataStr:nomunge, ivHex:nomunge";
    var sessKeyHex = des3KeyGen();
    //console.log('sessKeyHex: '+sessKeyHex +' len:'+sessKeyHex.length);

    var rsa = new RSAKey();
    rsa.setPublic(modulusHexStr, exponentHexStr);
    var encSessBlock = rsa.encrypt(new BigInteger(sessKeyHex, 16));
    //console.log('encSessBlock: '+encSessBlock +' len: '+encSessBlock.length);

    var encBlock = des3EncryptPKCS5Padding_CBC(sessKeyHex, dataStr, ivHex);
    //console.log('encBlock: '+encBlock +' len: '+encBlock.length);

    return encSessBlock+encBlock;
}

/**
 * @private
 * Algorithm:   Triple DES Encryption
 * Mode:        CBC
 * Padding:     PKCS5
 * @param {String}  des3KeyHex  Triple DES key represented in hex string.
 * @param {String}  dataStr        Data string to be encrypted.
 * @param {String}  ivHex       Initialization vector of 8 bytes represented in hex string.
 * @returns {String}  Triple DES ciphertext represented in hex string.
 */
function des3EncryptPKCS5Padding_CBC(des3KeyHex, dataStr, ivHex){
	 "des3KeyHex:nomunge, dataStr:nomunge, ivHex:nomunge";

	  var des3Key = Util.fromHexToString(des3KeyHex);
	  //console.log('des3Key: '+des3Key + ' len: '+des3Key.length);

	  var iv = Util.fromHexToString(ivHex);
	  //console.log('iv: '+iv + ' len: '+iv.length);

	  var CBC_MODE = 1;

	  return Util.stringToHex(des(des3Key, dataStr, 1, CBC_MODE, iv, 1));
}

/**
 * @private
 * Algorithm:   Triple DES Decryption
 * Mode:        CBC
 * Padding:     PKCS5
 * @param {String}  des3KeyHex  Triple DES key represented in hex string.
 * @param {String}  dataStrHex        Data hex string to be decrypted.
 * @param {String}  ivHex       Initialization vector of 8 bytes represented in hex string.
 * @returns {String}  Triple DES ciphertext represented in hex string.
 */

function des3DecryptPKCS5Padding_CBC(des3KeyHex, dataStrHex, ivHex){
	"des3KeyHex:nomunge, dataStr:nomunge, ivHex:nomunge";
	var des3Key = Util.fromHexToString(des3KeyHex);
	var iv = Util.fromHexToString(ivHex);
	var CBC_MODE = 1;
	return des(des3Key, Util.fromHexToString(dataStrHex), 0, CBC_MODE, iv, 1);

}


/**
 * @private
 * Triple DES key generation
 * @returns  {String} Triple DES key represented in hex string.
 */
function des3KeyGen(){
    var numOfBytes = 24;
    var rndArr = Util.randomBytes(numOfBytes); // get an array of random numbers
    if (!rndArr || (rndArr.length < numOfBytes)){
        alert("Random not generated");
        return null;
    }
    return Util.toHexString(rndArr);
}

