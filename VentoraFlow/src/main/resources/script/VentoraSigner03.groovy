import com.sap.gateway.ip.core.customdev.util.Message;

// used for accessing the PrivateKey by alias
import com.sap.it.api.ITApiFactory;
import com.sap.it.api.keystore.KeystoreService;

// used for digital signature verification. Built-in, so import statements are not required if variables not declared
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.Signature;

def Message processData(Message message) {

    // Content
    def body = message.getBody(java.lang.String) as String;
	byte[] bodyAsBytes = body.getBytes(); //convert body to byte[] is required for signature verification

    // Public Key
    KeystoreService keystoreService = ITApiFactory.getService(KeystoreService.class, null) // fetch the public key from the CPI keystore
    KeyPair keyPair  = keystoreService.getKeyPair("ventoraposdigicert"); 
	//PublicKey publicKey = keyPair.getPublic();
	PrivateKey pvtKey = keyPair.getPrivate();
    // Signature
    //def signature = message.getHeaders().get("SAPSimpleSignatureValue"); // read base64-encoded signature from header
    //byte[] signatureAsBytes = Base64.getDecoder().decode(signature);  // decode base64

    // Verify 
	Signature sig = Signature.getInstance("SHA256withRSA", "SunRsaSign"); // algorithms and the provider. "SunRsaSign" is a built-in provider that supports RSA
	//sig.initVerify(publicKey);
	sig.initSign(pvtKey);
	sig.update(bodyAsBytes);
	byte[] signedBody = sig.sign();

	def encodedMsg = Base64.getEncoder().encodeToString(signedBody);
	message.setBody(encodedMsg);

    return message;
}