import com.sap.gateway.ip.core.customdev.util.Message;
import java.util.Base64;

// used for accessing the PrivateKey by alias
import com.sap.it.api.ITApiFactory;
import com.sap.it.api.keystore.KeystoreService;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
// used for digital signature verification. Built-in, so import statements are not required if variables not declared
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.Signature;

def Message processData(Message message) {

    // Content
    def body = message.getBody(java.lang.String) as String;
	//byte[] bodyAsBytes = body.getBytes(); //convert body to byte[] is required for signature verification
    def slurper = new groovy.json.JsonSlurper();
    def messageBody = slurper.parseText(body); 
	
	def invInput = messageBody.InvoiceRaw;
	def pvtKey1 = messageBody.PrivateKey;
	
	message.setHeader("VentoraInvoice", invInput);
	message.setHeader("VentoraPrivateKey",pvtKey1);
	
	byte[] bodyAsBytes = invInput.getBytes()
    // Public Key
    //KeystoreService keystoreService = ITApiFactory.getService(KeystoreService.class, null) // fetch the public key from the CPI keystore
    //KeyPair keyPair  = keystoreService.getKeyPair("ventoraposdigicert"); 
	//PublicKey publicKey = keyPair.getPublic();
	//PrivateKey pvtKey = keyPair.getPrivate();
	
	//byte[] pvtKeyBytes = pvtKey.getEncoded();
	byte[] pvtKeyBytes = pvtKey1.getBytes();
	String pvtBase64 = Base64.getEncoder().encodeToString(pvtKeyBytes);
	
	message.setHeader("SimpleSignPrivateKey", pvtBase64);
	
    // Signature
    //def signature = message.getHeaders().get("SAPSimpleSignatureValue"); // read base64-encoded signature from header
    //byte[] signatureAsBytes = Base64.getDecoder().decode(signature);  // decode base64
  // Decode the Base64 string to a byte array
    def decodedKey = Base64.getDecoder().decode(pvtKey1);
    // Create the key specification
    def keySpec = new PKCS8EncodedKeySpec(decodedKey);
    def kf = KeyFactory.getInstance("RSA"); 
    def pvtKey2 = kf.generatePrivate(keySpec);
    
    // Verify 
	Signature sig = Signature.getInstance("SHA256withRSA", "SunRsaSign"); // algorithms and the provider. "SunRsaSign" is a built-in provider that supports RSA
	//sig.initVerify(publicKey);
	sig.initSign(pvtKey2);
	sig.update(bodyAsBytes);
	byte[] signedBody = sig.sign();

	def encodedMsg = Base64.getEncoder().encodeToString(signedBody);
	message.setBody(encodedMsg);

    return message;
}