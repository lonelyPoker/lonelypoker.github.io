### Base64编码

```java
import okio.ByteString;

public class Base64 {

    public static String encode(String plainText){
        return ByteString.of(plainText.getBytes()).base64();
    }

    public static String encodeURL(String plainText){
        return ByteString.of(plainText.getBytes()).base64Url();
    }
}
```

### Hex编码

```java
import okio.ByteString;

public class HEX {
    public static String encrypt(String plainText){
        ByteString byteString = ByteString.of(plainText.getBytes());
        return byteString.hex();
    }
    public static String decrypt(String cipherText){
        return ByteString.decodeHex(cipherText).utf8();
    }

}
```

### MD5信息摘要算法

```java
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import okio.ByteString;

public class MD5 {

    public static String getMD5(String plainText) throws NoSuchAlgorithmException {
        //    信息摘要算法MD5
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        md5.update((plainText+"MessageDigest").getBytes());
        byte[] bytes = md5.digest();
        String HexString =  ByteString.of(bytes).hex();
        String base64String =  ByteString.of(bytes).base64();
        return "\nHex:" + HexString + "\nbase64: " + base64String;
    }
}
```

### MAC信息摘要算法

```java
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import okio.ByteString;

public class MAC {
    public static String getMAC(String plainString) throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec hmacSHA1 = new SecretKeySpec("qgsoft21".getBytes(), "HmacSHA1");
        Mac hmacMD5 = Mac.getInstance("HmacSHA1");
        hmacMD5.init(hmacSHA1);
        hmacMD5.update(plainString.getBytes());
        byte[] hmacMD5String = hmacMD5.doFinal("saltstr".getBytes());
        String HexString = ByteString.of(hmacMD5String).hex();
        String base64String = ByteString.of(hmacMD5String).base64();
        return "\nHex:" + HexString + "\nbase64: " + base64String;
    }
}
```

### SHA信息摘要算法

```java
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import okio.ByteString;

public class SHA {

    public static String getSHA(String plainString) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        sha256.update((plainString+"MessageDigest").getBytes());
        String hexString = ByteString.of(sha256.digest()).hex();
        String base64String = ByteString.of(sha256.digest()).base64();
        return "\nHex:" + hexString + "\nbase64: " + base64String;
    }
}
```

### DES对称加密算法

```java
import android.util.Log;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import okio.ByteString;

public class DES {


    public static String Encrypt(String plainString) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec("12345678".getBytes(), "DES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec("12345678".getBytes());
        //Cipher instance = Cipher.getInstance("DES/ECB/PKCS5Padding");
        Cipher instance = Cipher.getInstance("DES/CBC/PKCS5Padding");
        instance.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] bytes = instance.doFinal("xiepenggxiepengg".getBytes());
        Log.d("DES", "des bytes: " + Arrays.toString(bytes));
        String HexString = ByteString.of(bytes).hex();
        String base64String = ByteString.of(bytes).base64();
        return "\nHex:" + HexString + "\nbase64: " + base64String;
    }


    public static String Decrypt(String cipherText) throws Exception{
        SecretKeySpec secretKeySpec = new SecretKeySpec("12345678".getBytes(), "DES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec("12345678".getBytes());
        Cipher instance = Cipher.getInstance("DES/CBC/PKCS5Padding");
        instance.init(Cipher.DECRYPT_MODE,secretKeySpec,ivParameterSpec);
//        instance.init(Cipher.DECRYPT_MODE,secretKeySpec);
        byte[] bytes = instance.doFinal(ByteString.decodeHex(cipherText).toByteArray());
        return new String(bytes);
    }
}
```

### RSA_BASE非对称加密算法

```java
import android.util.Log;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;

import okio.ByteString;

public class RSA_Base64 {

    public PublicKey generatePuclicKey(String publicKeyBase64) throws Exception {
        byte[] publicKeyBase64Bytes = ByteString.decodeBase64(publicKeyBase64).toByteArray();
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKeyBase64Bytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        return publicKey;
    }



    public PrivateKey generatePrivateKey(String privateKeyBase64) throws Exception{
        byte[] privateKeyBase64Bytes = ByteString.decodeBase64(privateKeyBase64).toByteArray();
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyBase64Bytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
    }


    public String encryptPublicKey(String plainString) throws Exception{

        PublicKey publicKey = generatePuclicKey("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDA4JVeuDPZtbinBEjX3q3Rg998\n" +
                "GBwNOzsjS13rJotMyZNtN1S7uXbSEAsaFbvR1WbUTsSA6ohtte2LvwNg4OujsX4w\n" +
                "jQrUSUxE6Zg183IVTzckOVXP18z4ZrbJzQrxfmGurFoIJNWFd1D9333IVdRN+rYN\n" +
                "KQk1Nr5y5HkJZnejBQIDAQAB");
        Cipher instance = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        instance.init(Cipher.ENCRYPT_MODE,publicKey);
        byte[] bytes = instance.doFinal(plainString.getBytes());
        Log.d("poker", "RSA bytes length: " + bytes.length);
        return ByteString.of(bytes).hex();
    }




    public String decryptPrivateKey(String CipherText) throws Exception{

        PrivateKey privateKey = generatePrivateKey("MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAMDglV64M9m1uKcE\n" +
                "SNferdGD33wYHA07OyNLXesmi0zJk203VLu5dtIQCxoVu9HVZtROxIDqiG217Yu/\n" +
                "A2Dg66OxfjCNCtRJTETpmDXzchVPNyQ5Vc/XzPhmtsnNCvF+Ya6sWggk1YV3UP3f\n" +
                "fchV1E36tg0pCTU2vnLkeQlmd6MFAgMBAAECgYA2+Qu5tniYyZF6kN8OH9qcx6BP\n" +
                "5zM/li0xzw5SsmarmRxa2ZVd9+tkzcvMQHuKv+8R/e1F7RK7akntNaEJ4LFoNKuB\n" +
                "9NfHsbKi0QEllHSLUcH8+a9py34i77NGukyJtufY3Umkn7C+Ow7/9SOd01PJm6Nf\n" +
                "mWFNlrml50L9ATTvgQJBAOfYSE2CNpgLLxVbwgAhjY3+Wh+gQr2FDf4l7sVsgLNk\n" +
                "JJvTZ7YdXY+LP6GF2/cNqu68vO/YT+Eu3DPnLqtDGCECQQDU+PdOMCs0wFvTmzBu\n" +
                "I58QL+mA6v64ZivB2j3BHZV2SMxCS9wgvspQp8iE4pk1KI/I+6PXpveByNAkrpOx\n" +
                "w15lAkAYVdRpBlTyqqHbjREU8HCqSdtt3GWE/RVV6udgI55ytf09uff13qk2avhX\n" +
                "3PQUv4OEoZz3U+42hbOpYwe8BEPhAkEAxcsb07AE0I8+OT7OMdw/ZEc7NBIL07KA\n" +
                "PR+1bt9M6ngdzAysOnU3bMUHA/N3mtk7AMxElIprIEwik47XeKcbyQJALvGSRN1u\n" +
                "oJIIWlW9T7DTFOiy9BaWfJ6XTogidYssCJP1391aYWDuAOjnenidYcrp3NQGS92Y\n" +
                "kH9giUivwB7fNg==");

        Cipher instance = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        instance.init(Cipher.DECRYPT_MODE,privateKey);
        byte[] bytes = instance.doFinal(ByteString.decodeHex(CipherText).toByteArray());
        Log.d("poker", "decryptPrivateKey: " + bytes);
        return new String(bytes);
    }
}
```

### RSA_HEX非对称加密算法

```java
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.Cipher;

import okio.ByteString;

public class RSA_Hex {


    public final static String publicExponent = "010001";
    public final static String privateExponent = "229e1ce3fb391168db6b89ddd3f366c74bb8555c105e0f4c9c453ba4663e5825f6487ddf447b5e5fd323119654e0e81af3cb2b60c32d67d2f10d81553cf6174f70e4892145dd6e19fa2ffc05fcfd2d5c835f3eb74c3974" +
            "7f537d1585799975c69055e444d3ad2dd94fffc0525a42279c084e7d26da97f4255e2a88ef10229b41";
    public final static String moudulus = "a0de76ca1bb820ffd0bd2b3ebfac42573649516b700e39a9d78ddb8b34f69f586406d3fa0426763a8382b0ca8ce21f09a31028964612066ea29d7ec5234b3599deaaf82916e0d6a4702b6e29d3bab800cad9251e06245c960f" +
            "7d81abde07db31278726d8fea2060b1219fd8be1f10c2ac3f70e8de6a53c719a2f629d944a6feb";


    public static PublicKey generatePublicKey() throws Exception {
        BigInteger n = new BigInteger(moudulus, 16);
        BigInteger e = new BigInteger(publicExponent, 16);
        RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(n, e);
        KeyFactory instance = KeyFactory.getInstance("RSA");
        return instance.generatePublic(rsaPublicKeySpec);
    }


    public static PrivateKey generatePrivateKey() throws Exception {
        BigInteger n = new BigInteger(moudulus, 16);
        BigInteger d = new BigInteger(privateExponent, 16);
        RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(n, d);
        KeyFactory instance = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = instance.generatePrivate(rsaPrivateKeySpec);
        return privateKey;
    }


    public static String encodePublicKey(String PlainText) throws Exception {
        PublicKey publicKey = generatePublicKey();
        Cipher instance = Cipher.getInstance("RSA/ECB/NOPadding");
        instance.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] bytes = instance.doFinal(PlainText.getBytes());
        return ByteString.of(bytes).hex();
    }


    public static String decodePrivateKey(String CipherHexText) throws Exception {
        PrivateKey privateKey = generatePrivateKey();
        Cipher instance = Cipher.getInstance("RSA/ECB/NOPadding");
        instance.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] hexBytes = ByteString.decodeHex(CipherHexText).toByteArray();
        byte[] bytes = instance.doFinal(hexBytes);
        return new String(bytes);
    }

}
```

