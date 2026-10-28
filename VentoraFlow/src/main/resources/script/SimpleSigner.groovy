import com.sap.gateway.ip.core.customdev.util.Message;

// used for accessing the PrivateKey by alias
import com.sap.it.api.ITApiFactory;
import com.sap.it.api.keystore.KeystoreService;

// used for digital signature verification. Built-in, so import statements are not required if variables not declared
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Signature;

def Message processData(Message message) {

    // Content
    def body = message.getBody(java.lang.String) as String;
	byte[] bodyAsBytes = body.getBytes(); //convert body to byte[] is required for signature verification

    // Public Key
    KeystoreService keystoreService = ITApiFactory.getService(KeystoreService.class, null) // fetch the public key from the CPI keystore
    KeyPair keyPair  = keystoreService.getKeyPair("{e21561e2-04d4-419d-b98a-d1c25309c2f2}"); 
	PublicKey publicKey = keyPair.getPublic();
	
    // Signature
    def signature = message.getHeaders().get("SAPSimpleSignatureValue"); // read base64-encoded signature from header
    byte[] signatureAsBytes = Base64.getDecoder().decode(signature);  // decode base64

    // Verify 
	Signature sig = Signature.getInstance("SHA256withRSA", "SunRsaSign"); // algorithms and the provider. "SunRsaSign" is a built-in provider that supports RSA
	sig.initVerify(publicKey);
	sig.update(bodyAsBytes);
	boolean verificationResult = sig.verify(signatureAsBytes);

    // Handle result	
    def messageLog = messageLogFactory.getMessageLog(message);
	messageLog.addAttachmentAsString("VerificationResult", "Verification result:  " + verificationResult, "text/plain");
	if(! verificationResult) throw new Exception("Verification of Digital Signature failed!")

    return message;
}