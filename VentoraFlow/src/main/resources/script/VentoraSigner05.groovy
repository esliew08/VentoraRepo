import com.sap.gateway.ip.core.customdev.util.Message;
import java.util.Base64;

// used for accessing the PrivateKey by alias
import com.sap.it.api.ITApiFactory;
import com.sap.it.api.keystore.KeystoreService;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Signature;

def Message processData(Message message) {

    // Content
    def body = message.getBody(java.lang.String) as String;
    def slurper = new groovy.json.JsonSlurper();
    def messageBody = slurper.parseText(body); 
	
	def invInput = messageBody.InvoiceRaw;

	message.setHeader("VentoraInvoice", invInput);

    def inv01Bytes = Base64.getDecoder().decode(invInput);	

    KeystoreService keystoreService = ITApiFactory.getService(KeystoreService.class, null) // fetch the public key from the CPI keystore
    KeyPair keyPair  = keystoreService.getKeyPair("ventoraposdigicert"); 

	PrivateKey pvtKey = keyPair.getPrivate();
	
    // Verify 
	Signature sig = Signature.getInstance("SHA256withRSA"); 
	sig.initSign(pvtKey);
	sig.update(inv01Bytes);
	byte[] signedBody = sig.sign();

   def messageSigned = Base64.getEncoder().encodeToString(signedBody);
   def messagePvtKey = Base64.getEncoder().encodeToString(pvtKey.getEncoded());
    
    def builder = new groovy.json.JsonBuilder();
    builder.SignedData {
      invoice messageSigned   
      pvtkey messagePvtKey    
    };
    
	def encodedMsg = builder.toPrettyString();
	message.setBody(encodedMsg);

    return message;
}