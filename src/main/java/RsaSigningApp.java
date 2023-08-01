import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RsaSigningApp {

    public static void main(String[] args) {

        String algorithm = "SHA256withRSA";
        String stringToSign = "this is a content that will be ecrypted.";
        String privateKeyString = "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAgwi2Ay8pwSKAgctKaL81qvBvsnUnje9E4LZj7+897FblfoBk5NhOvM3X2nL/gNZJdRMIs7P/jyldLIA8HRU9IwIDAQABAkADA9xMTnWDgCu80NSxfFTbzhSD4rY6Sdsn4IqEJtkh6wUO7NZCjX1M4p7fME8UbbvCdba0eSas++3nrWBHmaBhAiEA/1Gd9KMoyOO/CEoVoKDLxO8/MvI6QXU9hrArEz/BA2cCIQCDYjUUsGmbLJgE5r4WxWuW0v0PGnR0ZuPgvPbHmGv+5QIhAKpHCI1rc3vnSDSDFEF4e+3vkbqsieW2Bz6Yp2HDFzrpAiAFEu7f3KxHbOJ2Ff8zW+56xa02PxxOPocAb+vL64wILQIgW6iC9HMTomG6QrRspuNjlm9ynjF5uxjqaTYWdBGr3EA=";
        String publicKeyString = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAIMItgMvKcEigIHLSmi/Narwb7J1J43vROC2Y+/vPexW5X6AZOTYTrzN19py/4DWSXUTCLOz/48pXSyAPB0VPSMCAwEAAQ==";
        PrivateKey privateKey = privateKeyFromString(privateKeyString);
        PublicKey publicKey = publicKeyFromString(publicKeyString);

        try {
            // Signing
            Signature signature = Signature.getInstance(algorithm);
            signature.initSign(privateKey);
            signature.update(stringToSign.getBytes(StandardCharsets.UTF_8));
            byte[] signatureBytes = signature.sign();
            String base64EncSig = Base64.getEncoder().encodeToString(signatureBytes);
            System.out.println(base64EncSig);

            // Verifying
            Signature expectedSignature = Signature.getInstance(algorithm);
            expectedSignature.initVerify(publicKey);
            expectedSignature.update(stringToSign.getBytes(StandardCharsets.UTF_8));
            boolean verified = expectedSignature.verify(signatureBytes);
            System.out.println(verified);

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    private static PrivateKey privateKeyFromString(String input) {
        byte [] pkcs8EncodedBytes = Base64.getDecoder().decode(input);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    private static PublicKey publicKeyFromString(String input) {
        byte [] pkcs8EncodedBytes = Base64.getDecoder().decode(input);
        try {
            X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(pkcs8EncodedBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(X509publicKey);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }
}
