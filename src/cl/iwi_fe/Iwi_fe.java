/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cl.iwi_fe;

import cl.nic.dte.util.XMLUtil;
import java.io.File;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.xmlbeans.XmlException;
import org.apache.xmlbeans.XmlObject;

/**
 *
 * @author dgonzalezj
 */
public class Iwi_fe {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        Iwi_fe iwi_fe = new Iwi_fe();
        iwi_fe.dte();
    }
    
    public void dte(){
        try {
            String xml_name = "test.xml";
            XMLUtil xMLUtil = new XMLUtil ();
            XmlObject result = XmlObject.Factory.parse(new File(xml_name));
            byte[] fxml = xMLUtil.getCleanedII(result);
            String str = new String(fxml, "ISO-8859-1");
            new dte().add(str);
        } catch (XmlException ex) {
            Logger.getLogger(Iwi_fe.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Iwi_fe.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    
    
}
