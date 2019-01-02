/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cl.iwi_fe;

import cl.iwi.config.config;
import cl.nic.dte.TimbreException;
import cl.nic.dte.util.Utilities;
import cl.nic.dte.util.XMLUtil;
import cl.sii.siiDte.AUTORIZACIONDocument;
import cl.sii.siiDte.AutorizacionType;
import cl.sii.siiDte.DTEDefType;
import cl.sii.siiDte.DTEDocument;
import cl.sii.siiDte.EnvioDTEDocument;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.NoSuchPaddingException;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.xmlbeans.XmlCursor;
import org.apache.xmlbeans.XmlException;
import org.apache.xmlbeans.XmlObject;
import org.apache.xmlbeans.XmlOptions;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 *
 * @author dgonzalezj
 */
public class dte {
    
    private String BASIC_FILES_COMPANIES_PATH = null;
    private String BASIC_FILES_USERS_PATH = null;
    private String IDS_SII = null;
    private String RUT_SII = null;

    
    public dte() {
        this.loadConfig();
    }  
    
    /**
     * create XML signed
     * @param xml 
     */
    public void add(String xml){
        if(xml!=null){

            try {
                String xmlInput = xml.replaceAll("> <", "><");
                
                HashMap<String, String> namespaces = new HashMap<String, String>();
                namespaces.put("", "http://www.sii.cl/SiiDte");
                XmlOptions opts = new XmlOptions();
                opts.setLoadSubstituteNamespaces(namespaces);
                opts.setCharacterEncoding("ISO-8859-1");
                
                XMLUtil xMLUtil = new XMLUtil ();
                XmlObject result = XmlObject.Factory.parse(xml);
                byte[] fxml = xMLUtil.getCleanedII(result);
                String str = new String(fxml, "ISO-8859-1");
                
                DTEDocument doc = DTEDocument.Factory.parse(str,opts);
                
                xmlInput = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>"+doc.toString();
                xmlInput = new utils_dte().convertToUTF8(xmlInput);
                                
                this.generate_dte(xmlInput);
                
            } catch (XmlException | IOException ex) {
                Logger.getLogger(Iwi_fe.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }
    
    /**
     * generate XML file DTE & EnvioDTE
     * @param xml
     * @return 
     */
    public boolean generate_dte(String xml){
        try {
            
            HashMap<String, String> namespaces = new HashMap<String, String>();
            namespaces.put("", "http://www.sii.cl/SiiDte");
            XmlOptions opts = new XmlOptions();
            opts.setLoadSubstituteNamespaces(namespaces);
                        
            DTEDocument doc = DTEDocument.Factory.parse(xml);
            String dteType = doc.getDTE().getDocumento().getEncabezado()
                    .getIdDoc()
                    .getTipoDTE()
                    .toString();
            
            String cafS = BASIC_FILES_COMPANIES_PATH+"/caf/"+dteType+"/33.xml";
            
            AutorizacionType caf = AUTORIZACIONDocument.Factory.parse(
                    new File(cafS), opts).getAUTORIZACION();
            
            String certS = BASIC_FILES_USERS_PATH+"/cert/iwi.pfx";
            
            String planenvio = BASIC_FILES_COMPANIES_PATH+"/plantilla/"
                    +dteType+".xml";
            String plantillaEnvio = new Scanner(
                    new File(planenvio), "ISO-8859-1")
                    .useDelimiter("\\A").next();
            
            String passS = "Charlie12";
            // leo certificado y llave privada del archivo pkcs12
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(new FileInputStream(certS), passS.toCharArray());
            String alias = ks.aliases().nextElement();
            
            X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
            PrivateKey key = (PrivateKey) ks.getKey(alias, passS.toCharArray());
            
            int folio = 1;
            doc.getDTE().getDocumento().getEncabezado().getIdDoc()
                    .setFolio(folio);
            
            doc.getDTE().timbrar(caf.getCAF(), caf.getPrivateKey(null));
            
            opts.setSavePrettyPrint();
            opts.setSavePrettyPrintIndent(0);
            opts.setCharacterEncoding("ISO-8859-1");
            opts.setSaveImplicitNamespaces(namespaces);
            
            // Releo formateado
            doc = DTEDocument.Factory.parse(doc.newInputStream(opts), opts);
            
            // firmo
            doc.getDTE().sign(key, cert);
            // Guardo
            opts = new XmlOptions();
            opts.setCharacterEncoding("ISO-8859-1");
            opts.setSaveImplicitNamespaces(namespaces);
            doc.save(new File("temp.xml"), opts);
            
            // Construyo Envio
            EnvioDTEDocument envio = EnvioDTEDocument.Factory // la plantilla
                    .parse(plantillaEnvio);
            
            // Debo agregar el schema location (Sino SII rechaza)
            XmlCursor cursor = envio.newCursor();
            if (cursor.toFirstChild()) {
                cursor.setAttributeText(new QName(
                        "http://www.w3.org/2001/XMLSchema-instance",
                        "schemaLocation"),
                        "http://www.sii.cl/SiiDte EnvioDTE_v10.xsd");
            }
            // leo certificado y llave privada del archivo pkcs12
            KeyStore ks1 = KeyStore.getInstance("PKCS12");
            ks1.load(new FileInputStream(certS), passS.toCharArray());
            String alias1 = ks1.aliases().nextElement();
            
            X509Certificate x509 = (X509Certificate) ks1.getCertificate(alias1);
            String enviadorS = Utilities.getRutFromCertificate(x509);
            PrivateKey pKey = (PrivateKey) ks1.getKey(alias1, 
                    passS.toCharArray());
            
            // Asigno un ID
            envio.getEnvioDTE().getSetDTE().setID(IDS_SII);
            
            cl.sii.siiDte.EnvioDTEDocument.EnvioDTE.SetDTE.Caratula car = envio
                    .getEnvioDTE().getSetDTE().getCaratula();
            
            car.setRutReceptor(RUT_SII);
            car.setRutEnvia(enviadorS);
            
            // documentos a enviar
            HashMap<String, String> namespaces1 = new HashMap<String, String>();
            namespaces1.put("", "http://www.sii.cl/SiiDte");
            XmlOptions opts1 = new XmlOptions();
            opts1.setLoadSubstituteNamespaces(namespaces1);
            
            
            DTEDefType[] dtes = new DTEDefType[1];
            HashMap<Integer, Integer> hashTot = new HashMap<Integer, Integer>();
            
            dtes[0] = DTEDocument.Factory.parse(
                    new FileInputStream("temp.xml"), opts1).getDTE();
            // armar hash para totalizar por tipoDTE
            if (hashTot.get(dtes[0].getDocumento().getEncabezado().getIdDoc()
                    .getTipoDTE().intValue()) != null) {
                hashTot.put(dtes[0].getDocumento().getEncabezado()
                        .getIdDoc()
                        .getTipoDTE().intValue(), hashTot.get(dtes[0]
                                .getDocumento()
                                .getEncabezado()
                                .getIdDoc()
                                .getTipoDTE()
                                .intValue()) + 1);
            } else {
                hashTot.put(dtes[0].getDocumento().getEncabezado().getIdDoc()
                        .getTipoDTE().intValue(), 1);
            }
            
            EnvioDTEDocument.EnvioDTE.SetDTE.Caratula.SubTotDTE[] subtDtes = 
                    new EnvioDTEDocument.EnvioDTE.SetDTE.Caratula
                    .SubTotDTE[hashTot.size()];
            int i = 0;
            for (Integer tipo : hashTot.keySet()) {
                EnvioDTEDocument.EnvioDTE.SetDTE.Caratula.SubTotDTE subt = 
                        EnvioDTEDocument.EnvioDTE.SetDTE.Caratula.SubTotDTE
                                .Factory.newInstance();
                subt.setTpoDTE(new BigInteger(tipo.toString()));
                subt.setNroDTE(new BigInteger(hashTot.get(tipo).toString()));
                subtDtes[i] = subt;
                i++;
            }
            
            car.setSubTotDTEArray(subtDtes);
            
            opts1 = new XmlOptions();
            opts1.setSavePrettyPrint();
            opts1.setSavePrettyPrintIndent(0);
            envio = EnvioDTEDocument.Factory.parse(envio.newInputStream(opts1));
            
            envio.getEnvioDTE().getSetDTE().setDTEArray(dtes);
            
            // firmo
            envio.sign(pKey, x509);
            opts1 = new XmlOptions();
            opts1.setCharacterEncoding("ISO-8859-1");
            String resultS = BASIC_FILES_COMPANIES_PATH+"/DTEs/"+
                    dteType+'/'+folio+".xml";
            envio.save(new File(resultS), opts1);
            Logger.getLogger(Iwi_fe.class.getName())
                    .log(Level.FINE, null, "Documento Creado");
            return true;
        } catch (XmlException | IOException | KeyStoreException | 
                NoSuchAlgorithmException | CertificateException | 
                UnrecoverableKeyException | NoSuchPaddingException | 
                InvalidKeySpecException | InvalidAlgorithmParameterException | 
                TimbreException | SignatureException | KeyException | 
                MarshalException | XMLSignatureException | SAXException | 
                ParserConfigurationException ex) {
            Logger.getLogger(Iwi_fe.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return false;
    }
    
    /**
     * load config variables properties
     */
    private void loadConfig() {
        try {
            config config = new config();
            BASIC_FILES_COMPANIES_PATH = 
                    config.getValues("BASIC_FILES_COMPANIES_PATH");
            BASIC_FILES_USERS_PATH = config.getValues("BASIC_FILES_USERS_PATH");
            IDS_SII = config.getValues("IDS_SII");
            RUT_SII = config.getValues("RUT_SII");
        } catch (IOException ex) {
            Logger.getLogger(dte.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
