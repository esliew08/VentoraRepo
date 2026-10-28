import com.sap.gateway.ip.core.customdev.util.Message;
import groovy.json.JsonSlurper

//code
def Message processData(Message message) 
{
    //Body 
    def body = message.getBody(java.io.Reader);
   // def jsonPayload = new JsonSlurper().parseText(body);

   def slurper = new JsonSlurper();
   def outputmsg = slurper.parseText(body.event.InvoiceRaw)

    message.setBody(outputmsg.toPrettyString()); 
    return message;
}