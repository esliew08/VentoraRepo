import com.sap.gateway.ip.core.customdev.util.Message;
import java.util.Base64;
import java.nio.charset.StandardCharsets;

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
	
	//byte[] bodyAsBytes = invInput.getBytes()
    def inv01Bytes = Base64.getDecoder().decode(invInput);	
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
    //def decodedKey = Base64.getDecoder().decode(pvtKey1);
    // Create the key specification
    //def keySpec = new PKCS8EncodedKeySpec(decodedKey);
    def keySpec = new PKCS8EncodedKeySpec(pvtKeyBytes);
    def kf = KeyFactory.getInstance("RSA"); 
    def pvtKey2 = kf.generatePrivate(keySpec);
    
    // Verify 
//	Signature sig = Signature.getInstance("SHA256withRSA", "SunRsaSign"); // algorithms and the provider. "SunRsaSign" is a built-in provider that supports RSA
	Signature sig = Signature.getInstance("SHA256withRSA"); 
	//sig.initVerify(publicKey);
	sig.initSign(pvtKey2);
	sig.update(inv01Bytes);
	byte[] signedBody = sig.sign();

   def messageSigned = Base64.getEncoder().encodeToString(signedBody);
   def messagePvtKey = Base64.getEncoder().encodeToString(pvtKey2.getEncoded());
    
    def builder = new groovy.json.JsonBuilder();
    builder.SignedData {
      invoice messageSigned   
      pvtkey messagePvtKey    
    };
    
	//def encodedMsg = Base64.getEncoder().encodeToString(signedBody);
	def encodedMsg = builder.toPrettyString();
	message.setBody(encodedMsg);

    return message;
}