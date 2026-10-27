import com.sap.gateway.ip.core.customdev.util.Message;
import groovy.json.JsonSlurper

//code
def Message processData(Message message) 
{
    //Body 
    //def body = message.getBody(java.io.Reader);
    //def json = new JsonSlurper().parseText(body);
    //def temp = json.main.temp;
    //message.setProperty("temperature",temp);
    //message.setProperty("isHot", temp > 35);
    //message.setProperty("condition",(temp>35) ? "Hot" : "Normal");
    return message;
}