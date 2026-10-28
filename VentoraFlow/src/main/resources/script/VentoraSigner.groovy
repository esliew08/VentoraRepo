import com.sap.gateway.ip.core.customdev.util.Message;
import java.util.HashMap;
import com.sap.it.api.ITApiFactory;
import com.sap.it.api.keystore.KeystoreService;
import java.security.KeyPair;
import java.security.PublicKey;
import javax.crypto.Cipher;


def Message processData(Message message) {

    // get nessage as byte array
    def body = message.getBody() as String;
    byte[] bodyAsBytes = body.getBytes();

    // fetch the public key from CPI Keystore
    KeystoreService keystoreService = ITApiFactory.getService(KeystoreService.class, null) 
    KeyPair keyPair  = keystoreService.getKeyPair("{e21561e2-04d4-419d-b98a-d1c25309c2f2}"); 
    PublicKey pubKey = keyPair.getPublic();

    // Encrypt
    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    // Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.ENCRYPT_MODE, pubKey);
    // byte[] input = "Dummy text".getBytes();	  
    cipher.update(bodyAsBytes);
    byte[] encryptedMsg = cipher.doFinal();	 

    // base64-encode the encrypted message
    def encodedMsg = Base64.getEncoder().encodeToString(encryptedMsg);

    message.setBody(encodedMsg);
    return message;
}