/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package cl.iwi_fe;

import cl.nic.dte.TimbreException;
import cl.nic.dte.net.ConexionSii;
import cl.nic.dte.net.ConexionSiiException;
import cl.nic.dte.util.Utilities;
import cl.sii.siiDte.AutorizacionType;
import cl.sii.siiDte.RECEPCIONDTEDocument;
import cl.sii.siiDte.boletas.BOLETADefType;
import cl.sii.siiDte.boletas.EnvioBOLETADocument;
import cl.sii.siiDte.libroCV.LibroCompraVentaDocument;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.math.BigDecimal;
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
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;
import java.util.regex.PatternSyntaxException;
import javax.activation.DataHandler;
import javax.activation.FileDataSource;
import javax.crypto.NoSuchPaddingException;
import javax.mail.BodyPart;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.servlet.http.HttpServletResponse;
import javax.xml.XMLConstants;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.soap.SOAPException;
import javax.xml.transform.Source;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import org.apache.commons.collections.MultiMap;
import org.apache.commons.collections.map.MultiValueMap;
import org.apache.log4j.Logger;
import org.apache.xmlbeans.XmlException;
import org.apache.xmlbeans.XmlOptions;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.DefaultHandler;


/**
 *
 * @author claudio
 */
public class UtilsDte {
  
    
    
    public RECEPCIONDTEDocument sendDTE(Logger log,String dteUrl, String rut,String pass,String certUrl){
        try {
            ConexionSii con = new ConexionSii();
            // leo certificado y llave privada del archivo pkcs12
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(new FileInputStream(certUrl), pass.toCharArray());
            String alias = ks.aliases().nextElement();
            log.debug("3.- Usando certificado " + alias
                    + " del archivo PKCS12: " + certUrl);
            
            X509Certificate x509 = (X509Certificate) ks.getCertificate(alias);
            PrivateKey pKey = (PrivateKey) ks.getKey(alias, pass.toCharArray());
            String token=null;
            do{
                token = con.getToken(pKey, x509);
            }while(token==null);
            
            System.out.println("Token: " + token);
            log.debug("Exception=[Obteniendo token de SII] MSG=[Token:"+token+"]");            
            String enviadorS = Utilities.getRutFromCertificate(x509);

//            EnvioDTEDocument envDoc = EnvioDTEDocument.Factory.parse(new File(
//                            dteUrl));

            RECEPCIONDTEDocument recp = con.uploadEnvioCertificacion(enviadorS, rut,
                    new File(dteUrl), token);
            
//            String status = String.valueOf(recp.getRECEPCIONDTE().getSTATUS());
//
//            String tipo = String.valueOf(envDoc.getEnvioDTE().getSetDTE().getDTEArray(0).getDocumento().
//                            getEncabezado().getIdDoc().getTipoDTE().intValue());
//            String folio = Long.toString(envDoc.getEnvioDTE().getSetDTE().getDTEArray(0).getDocumento().
//                            getEncabezado().getIdDoc().getFolio());
//            String trackId = recp.getRECEPCIONDTE().getTRACKID();
            if(recp.getRECEPCIONDTE().getTRACKID()!=null){
                log.debug("DTE enviado trackID:["+recp.getRECEPCIONDTE().getTRACKID()+"]");
            }else{
                log.debug("No se envio DTE");
            }
            
            return recp;
        } catch (KeyStoreException |org.apache.http.ParseException| ConexionSiiException|IOException|XmlException|NoSuchAlgorithmException ex) {
           log.error(" Exception = ["+ex.getMessage()+"] ");
        }catch (UnrecoverableKeyException|CertificateException|InvalidAlgorithmParameterException|KeyException|MarshalException | XMLSignatureException | SAXException | ParserConfigurationException | UnsupportedOperationException | SOAPException ex) {
            log.error(" Exception = ["+ex.getMessage()+"] MSG=[]");
        } 
        return null;
    }
    public RECEPCIONDTEDocument sendDTEProduccion(Logger log,String dteUrl, String rut,String pass,String certUrl){
        try {
            ConexionSii con = new ConexionSii();
            // leo certificado y llave privada del archivo pkcs12
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(new FileInputStream(certUrl), pass.toCharArray());
            String alias = ks.aliases().nextElement();
            log.debug("3.- Usando certificado " + alias
                    + " del archivo PKCS12: " + certUrl);
            
            X509Certificate x509 = (X509Certificate) ks.getCertificate(alias);
            PrivateKey pKey = (PrivateKey) ks.getKey(alias, pass.toCharArray());
            String token=null;
            do{
                token = con.getToken(pKey, x509);
            }while(token==null);
            
            System.out.println("Token: " + token);
            log.debug("Exception=[Obteniendo token de SII] MSG=[Token:"+token+"]");            
            String enviadorS = Utilities.getRutFromCertificate(x509);

//            EnvioDTEDocument envDoc = EnvioDTEDocument.Factory.parse(new File(
//                            dteUrl));

            RECEPCIONDTEDocument recp = con.uploadEnvioProduccion(enviadorS, rut,
                    new File(dteUrl), token);
            
//            String status = String.valueOf(recp.getRECEPCIONDTE().getSTATUS());
//
//            String tipo = String.valueOf(envDoc.getEnvioDTE().getSetDTE().getDTEArray(0).getDocumento().
//                            getEncabezado().getIdDoc().getTipoDTE().intValue());
//            String folio = Long.toString(envDoc.getEnvioDTE().getSetDTE().getDTEArray(0).getDocumento().
//                            getEncabezado().getIdDoc().getFolio());
//            String trackId = recp.getRECEPCIONDTE().getTRACKID();
            if(recp.getRECEPCIONDTE().getTRACKID()!=null){
                log.debug("DTE enviado trackID:["+recp.getRECEPCIONDTE().getTRACKID()+"]");
            }else{
                log.debug("No se envio DTE");
            }
            
            return recp;
        } catch (KeyStoreException |org.apache.http.ParseException| ConexionSiiException|IOException|XmlException|NoSuchAlgorithmException ex) {
           log.error(" Exception = ["+ex.getMessage()+"] ");
        }catch (UnrecoverableKeyException|CertificateException|InvalidAlgorithmParameterException|KeyException|MarshalException | XMLSignatureException | SAXException | ParserConfigurationException | UnsupportedOperationException | SOAPException ex) {
            log.error(" Exception = ["+ex.getMessage()+"] MSG=[]");
        } 
        return null;
    }
    
    public String scapeSpecialCharacterII(Logger log,String original){
        try {
            byte[] utf8Bytes = original.getBytes("UTF8");
            byte[] defaultBytes = original.getBytes();
            
            String roundTrip = new String(utf8Bytes, "UTF8");
            return roundTrip;
        } catch (UnsupportedEncodingException ex) {
           log.error("Type=[Controller] Function =[updateStatusDTE] Exception["+ex.getMessage()+"] MSG=[No se pudo actualizar la DTE]");
        }
        return null;
        
    }
    
    public String convertToUTF8(String s) {
        String out = null;
        try {
            out = new String(s.getBytes("UTF-8"), "ISO-8859-1");
        } catch (java.io.UnsupportedEncodingException e) {
            return null;
        }
        return out;
    }
    
    public String convertFromUTF8(String s) {
        String out = null;
        try {
            out = new String(s.getBytes("ISO-8859-1"), "UTF-8");
        } catch (java.io.UnsupportedEncodingException e) {
            return null;
        }
        return out;
    }
    
    public void sendMessageClient(int type,String cod,String desc,int folio,String idDoc,int dteType,HttpServletResponse response,Logger log){
        String xmlSend = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
        switch(type){
            case 1:{//message save
                try {
                    xmlSend +="<aw>\n" +
                                "<status>\n" +
                                    "<cod>"+cod+"</cod>\n" +
                                    "<desc>"+desc+"</desc>\n" +
                                "</status>\n" +
                                "<dte>\n" +
                                    "<folio>"+folio+"</folio>\n" +
                                    "<idDoc>"+idDoc+"</idDoc>\n" +
                                "</dte>\n" +
                            "</aw>";
                    response.getWriter().write(xmlSend);
                }catch (IOException ex) {
                    response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                    log.warn("EXCEPTION["+ex.getMessage()+"] MSG=[No se puede responder al status]");
                }
                break;
            }
            case 2: {//message getStatus Dte
                try{
                    xmlSend +="<aw>\n" +
                                "<status>\n" +
                                        "<cod>"+cod+"</cod>\n" +
                                        "<desc>"+desc+"</desc>\n" +
                                    "</status>\n" +
                                    "<dte>\n" +
                                        "<folio>"+folio+"</folio>\n" +
                                        "<trackID>"+idDoc+"</trackID>\n" +
                                        "<DTEType>"+dteType+"</DTEType>\n"+
                                    "</dte>\n" +
                              "</aw>";
                    response.getWriter().write(xmlSend);
                }catch(Exception ex){
                    response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                    log.warn("EXCEPTION["+ex.getMessage()+"] MSG=[No se puede responder al status]");
                }
                break;
            }
        }
    }
    
    public LibroCompraVentaDocument bookGenerate(Logger log,String urlFile, int operType,String period,int sendType,int bookType,String rutEnvia){
        try {
                        HashMap<String, String> namespaces = new HashMap<String, String>();
                        namespaces.put("", "http://www.sii.cl/SiiDte");
                        XmlOptions opts = new XmlOptions();
                        opts.setLoadSubstituteNamespaces(namespaces);

                        LibroCompraVentaDocument libro= LibroCompraVentaDocument.Factory.parse(new File(urlFile),opts);

                        libro.getLibroCompraVenta().getEnvioLibro().getCaratula().
                                setRutEnvia(rutEnvia);
                        String[] data = period.split("-");
                        Calendar calendar = new GregorianCalendar(Integer.valueOf(data[0]), Integer.valueOf(data[1])-1, 01);
                        
                        libro.getLibroCompraVenta().getEnvioLibro().getCaratula().setPeriodoTributario(calendar);

                        libro.getLibroCompraVenta().getEnvioLibro().getCaratula().setTipoOperacion(LibroCompraVentaDocument
                                .LibroCompraVenta.EnvioLibro.Caratula.TipoOperacion.Enum.forInt(operType));


                        libro.getLibroCompraVenta().getEnvioLibro().getCaratula().setTipoLibro(LibroCompraVentaDocument
                                .LibroCompraVenta.EnvioLibro.Caratula.TipoLibro.Enum.forInt(bookType));

                        libro.getLibroCompraVenta().getEnvioLibro().getCaratula().setTipoEnvio(LibroCompraVentaDocument
                                .LibroCompraVenta.EnvioLibro.Caratula.TipoEnvio.Enum.forInt(sendType));

                        return libro;
            } catch (IOException ex) {
                log.error("EXCEPTION=["+ex.getMessage()+"] MSG=[Error al leer el Documento] ");
            } catch (XmlException ex) {
                log.error("EXCEPTION=["+ex.getMessage()+"] MSG=[Error al tratar el xml] ");
            }catch(PatternSyntaxException ex){
                log.error("EXCEPTION=["+ex.getMessage()+"] MSG=[Error al rescatar el Accounting Period] ");
            }
        return null;
    }
    
      
    public LibroCompraVentaDocument addPeriodResume(Map dte, LibroCompraVentaDocument book){
        
        Long codIVANoRec = null,totOpIVANoRec = null,totMntIVANoRec = null;
        book.getLibroCompraVenta().getEnvioLibro().addNewResumenPeriodo();
        Iterator it = dte.entrySet().iterator();
        int i=0;
        while(it.hasNext()){
            Map.Entry n = (Map.Entry)it.next();
            if(n!=null){
                TreeMap map  =  (TreeMap) n.getValue();
                Iterator m = map.entrySet().iterator();
                book.getLibroCompraVenta().getEnvioLibro().getResumenPeriodo().addNewTotalesPeriodo();
                 while(m.hasNext()){
                    Map.Entry s = (Map.Entry)m.next();
                    if(s.getKey().equals("A-TpoDoc")&&s.getValue()!=null){
                        int val = Integer.valueOf((String) s.getValue());
                        book.getLibroCompraVenta().getEnvioLibro().getResumenPeriodo().getTotalesPeriodoArray(i).setTpoDoc(BigInteger.valueOf(val));
                    }
                    if(s.getKey().equals("B-TotDoc")&&s.getValue()!=null){
                        int val = Integer.valueOf((String) s.getValue());
                        book.getLibroCompraVenta().getEnvioLibro().getResumenPeriodo().getTotalesPeriodoArray(i).setTotDoc(val);
                    }
                    
                    if(s.getKey().equals("C-MntNeto")){
                         if (s.getValue()!=null) {
                            int val = Integer.valueOf((String) s.getValue());
                            book.getLibroCompraVenta().getEnvioLibro().getResumenPeriodo().getTotalesPeriodoArray(i).setTotMntNeto(val);
                        } else {
                            book.getLibroCompraVenta().getEnvioLibro().getResumenPeriodo().getTotalesPeriodoArray(i).setTotMntNeto(0);
                        }
                    }
                    if(s.getKey().equals("D-MntExe")){
                        if (s.getValue()!=null) {
                            int val = Integer.valueOf((String) s.getValue());
                            book.getLibroCompraVenta().getEnvioLibro().getResumenPeriodo().getTotalesPeriodoArray(i).setTotMntExe(val);
                        } else {
                            book.getLibroCompraVenta().getEnvioLibro().getResumenPeriodo().getTotalesPeriodoArray(i).setTotMntExe(0);
                        }
                    }
                    if(s.getKey().equals("E-MntIVA")){
                        if (s.getValue()!=null) {
                            int val = Integer.valueOf((String) s.getValue());
                            book.getLibroCompraVenta().getEnvioLibro().getResumenPeriodo().getTotalesPeriodoArray(i).setTotMntIVA(val);
                        } else {
                            book.getLibroCompraVenta().getEnvioLibro().getResumenPeriodo().getTotalesPeriodoArray(i).setTotMntIVA(0);
                        }
                    }
                    if(s.getKey().equals("G-MntTotal")){
                        if (s.getValue()!=null) {
                            int val = Integer.valueOf((String) s.getValue());
                            book.getLibroCompraVenta().getEnvioLibro().getResumenPeriodo().getTotalesPeriodoArray(i).setTotMntTotal(val);
                        } else {
                            book.getLibroCompraVenta().getEnvioLibro().getResumenPeriodo().getTotalesPeriodoArray(i).setTotMntTotal(0);
                        }
                    }
                    if(s.getKey().equals("F-IVAUsoComun")&&s.getValue()!=null){
                        long val = Long.valueOf(s.getValue().toString());
                        double fact = 0.6;
                        long totCred = (long) ((fact)*val);
                        book.getLibroCompraVenta().getEnvioLibro().getResumenPeriodo().getTotalesPeriodoArray(i).setTotIVAUsoComun(val);
                        book.getLibroCompraVenta().getEnvioLibro().getResumenPeriodo().getTotalesPeriodoArray(i).setFctProp(BigDecimal.valueOf(fact));
                        book.getLibroCompraVenta().getEnvioLibro().getResumenPeriodo().getTotalesPeriodoArray(i).setTotCredIVAUsoComun(totCred);
                    }
                    if(s.getKey().equals("H-MontoImp")&&s.getValue()!=null){
                        Long val = Long.valueOf(s.getValue().toString());
                        book.getLibroCompraVenta().getEnvioLibro().getResumenPeriodo().getTotalesPeriodoArray(i).setTotIVARetTotal(val);
                        book.getLibroCompraVenta().getEnvioLibro().getResumenPeriodo().getTotalesPeriodoArray(i).addNewTotOtrosImp();
                        book.getLibroCompraVenta().getEnvioLibro().getResumenPeriodo().getTotalesPeriodoArray(i).getTotOtrosImpArray(0).setCodImp(BigInteger.valueOf(15));
                        //                        book.getLibroCompraVenta().getEnvioLibro().getResumenPeriodo().getTotalesPeriodoArray(i).setTotIVARetTotal(val);
                        book.getLibroCompraVenta().getEnvioLibro().getResumenPeriodo().getTotalesPeriodoArray(i).getTotOtrosImpArray(0).setTotMntImp(val);
                    }
                    
                    if(s.getKey().equals("I-CodIVANoRec")&& !s.getValue().equals("0")){
//                        codIVANoRec = Long.valueOf(s.getValue().toString());
                        codIVANoRec = Long.valueOf(4);
                    }
                    if(s.getKey().equals("J-TotOpIVANoRec")&& !s.getValue().equals("0")){
                        totOpIVANoRec = Long.valueOf(s.getValue().toString());
                    }
                    if(s.getKey().equals("K-TotMntIVANoRec")&& s.getValue()!=null){
                        totMntIVANoRec = Long.valueOf(s.getValue().toString());
                    }
                    
                    if(s.getKey().equals("L-TotIVANoRec") && s.getValue().equals("1")){
                        book.getLibroCompraVenta().getEnvioLibro().getResumenPeriodo().getTotalesPeriodoArray(i).addNewTotIVANoRec();
                        book.getLibroCompraVenta().getEnvioLibro().getResumenPeriodo().getTotalesPeriodoArray(i).getTotIVANoRecArray(0).setCodIVANoRec(BigInteger.valueOf(codIVANoRec));
                        book.getLibroCompraVenta().getEnvioLibro().getResumenPeriodo().getTotalesPeriodoArray(i).getTotIVANoRecArray(0).setTotOpIVANoRec(totOpIVANoRec);
                        book.getLibroCompraVenta().getEnvioLibro().getResumenPeriodo().getTotalesPeriodoArray(i).getTotIVANoRecArray(0).setTotMntIVANoRec(totMntIVANoRec);
                    }
                 }
                 i+=1;
            }
            
        }
        return book;
    }
    /*se tiene que agregar un EnvioLibroDetalle*/
    public LibroCompraVentaDocument addDetailToBook
        (Logger log,Map dte, LibroCompraVentaDocument book){
           
        Iterator it = dte.entrySet().iterator();
        int i=0;
        double tasaImp = 0 ;
        while(it.hasNext()){
             Map.Entry e = (Map.Entry) it.next();
             if (e!=null) {
                HashMap map  =  (HashMap) e.getValue();
                Iterator m = map.entrySet().iterator();
                        
                book.getLibroCompraVenta().getEnvioLibro().insertNewDetalle(i);
                book.getLibroCompraVenta().getEnvioLibro().getDetalleArray(i).setOperacion(BigInteger.valueOf(1));
                while(m.hasNext()){
                    Map.Entry n = (Map.Entry)m.next();
                    
                    if(n.getKey().equals("TpoDoc")&&n.getValue()!=null){
                        int val = Integer.valueOf((String) n.getValue());
                        book.getLibroCompraVenta().getEnvioLibro().getDetalleArray(i).setTpoDoc(BigInteger.valueOf(val));
                    }
                    if(n.getKey().equals("NroDoc")&&n.getValue()!=null){
                        book.getLibroCompraVenta().getEnvioLibro().getDetalleArray(i).setNroDoc(Integer.valueOf(n.getValue().toString()));
                    }
                    if(n.getKey().equals("TasaImp")){
                        if(n.getValue()!=null){
                            tasaImp = Double.valueOf(19.0);
                            book.getLibroCompraVenta().getEnvioLibro().getDetalleArray(i).setTasaImp(BigDecimal.valueOf(tasaImp));
                        }else{
                            book.getLibroCompraVenta().getEnvioLibro().getDetalleArray(i).setTasaImp(BigDecimal.valueOf(0));
                        }
                        
                    }
                    if(n.getKey().equals("RznDoc")&&n.getValue()!=null){
                        book.getLibroCompraVenta().getEnvioLibro().getDetalleArray(i).setRznSoc(n.getValue().toString());
                    }
                    if(n.getKey().equals("MntTotal")&&n.getValue()!=null){
                        Long val = Long.valueOf(n.getValue().toString());
                        book.getLibroCompraVenta().getEnvioLibro().getDetalleArray(i).setMntTotal(val);
                    }
                    if(n.getKey().equals("MntIVA")){
                        if(n.getValue()==null){
                            book.getLibroCompraVenta().getEnvioLibro().getDetalleArray(i).setMntIVA(0);
                        }else{
                            Long val = Long.valueOf(n.getValue().toString());
                            book.getLibroCompraVenta().getEnvioLibro().getDetalleArray(i).setMntIVA(val);
                        }
                    }
                    if(n.getKey().equals("FchDoc")&&n.getValue()!=null){
//                        Calendar val =Calendar.getInstance();
//                        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
//                        val.setTime(sdf.parse(n.getValue().toString()));
                        String[] data = n.getValue().toString().split("-");
                        Calendar calendar = new GregorianCalendar(Integer.valueOf(data[0]), Integer.valueOf(data[1])-1, Integer.valueOf(data[2]));
                        book.getLibroCompraVenta().getEnvioLibro().getDetalleArray(i).setFchDoc(calendar);
                    }
                    if(n.getKey().equals("MntExe")&&n.getValue()!=null){
                        Long val = Long.valueOf(n.getValue().toString());
                        book.getLibroCompraVenta().getEnvioLibro().getDetalleArray(i).setMntExe(val);
                    }
                    if(n.getKey().equals("MntNeto")){
                        if(n.getValue()==null){
                           book.getLibroCompraVenta().getEnvioLibro().getDetalleArray(i).setMntNeto(0);
                       }else{
                            Long val = Long.valueOf(n.getValue().toString());
                            book.getLibroCompraVenta().getEnvioLibro().getDetalleArray(i).setMntNeto(val);
                        }
                    }
                    if(n.getKey().equals("RUTRecep")&&n.getValue()!=null){
                        book.getLibroCompraVenta().getEnvioLibro().getDetalleArray(i).setRUTDoc(n.getValue().toString());
                    }
                    if(n.getKey().equals("IVAUsoComun")&&n.getValue()!=null&&!n.getValue().equals("0")){
                        Long val = Long.valueOf(n.getValue().toString());
                        book.getLibroCompraVenta().getEnvioLibro().getDetalleArray(i).setIVAUsoComun(val);
                    }
                    
                    if(n.getKey().equals("TipoImp")&&n.getValue()!=null){
//                        double tasa1 = tasaImp;
//                        BigDecimal tasa = new BigDecimal(String.valueOf(tasa1));
                        Long val = Long.valueOf(n.getValue().toString());
                        book.getLibroCompraVenta().getEnvioLibro().getDetalleArray(i).getOtrosImpArray(0).setCodImp(BigInteger.valueOf(val));
                        book.getLibroCompraVenta().getEnvioLibro().getDetalleArray(i).getOtrosImpArray(0).setTasaImp(BigDecimal.valueOf(19));
                        
//                        book.getLibroCompraVenta().getEnvioLibro().getDetalleArray(i).setIVARetTotal(val);
                    }
                    if(n.getKey().equals("MontoImp")&&n.getValue()!=null){
//                        Long val = Long.valueOf(n.getValue().toString());
//                        Long val = Long.valueOf("1725");
//                        book.getLibroCompraVenta().getEnvioLibro().getDetalleArray(i).setIVARetTotal(val);
//                        LibroCompraVentaDocument.LibroCompraVenta.EnvioLibro.Detalle.OtrosImp otrosImpArray = 
//                        book.getLibroCompraVenta().getEnvioLibro().getDetalleArray(i).insertNewOtrosImp(0);
                        book.getLibroCompraVenta().getEnvioLibro().getDetalleArray(i).setIVARetTotal(Integer.parseInt(n.getValue().toString()));
                        book.getLibroCompraVenta().getEnvioLibro().getDetalleArray(i).insertNewOtrosImp(0);
                        book.getLibroCompraVenta().getEnvioLibro().getDetalleArray(i).getOtrosImpArray(0).setMntImp(Integer.parseInt(n.getValue().toString()));
                    }
                    
                    if(n.getKey().equals("TotIVANoRec")&& n.getValue()!=null){
                        book.getLibroCompraVenta().getEnvioLibro().getDetalleArray(i).addNewIVANoRec();
                    }
                    if(n.getKey().equals("CodIVANoRec")&&n.getValue()!=null){
                        Long val = Long.valueOf(n.getValue().toString());
                        book.getLibroCompraVenta().getEnvioLibro().getDetalleArray(i).getIVANoRecArray(0).setCodIVANoRec(BigInteger.valueOf(val));
                    }
                    if(n.getKey().equals("TotMntIVANoRec")&&n.getValue()!=null){
                        Long val = Long.valueOf(n.getValue().toString());
                        book.getLibroCompraVenta().getEnvioLibro().getDetalleArray(i).getIVANoRecArray(0).setMntIVANoRec(val);
                    }
                }
            }
             i++;
        }
      
        return book;
    }
    
    public int countCharacterX(char character,String chain){
        int value = 0;
        if(chain!=null||!chain.equals("")){
            for (int i = 0; i < chain.length(); i++) {
                char c = chain.charAt(i);
                if(character==c){
                    value++;
                }
            }
        }
        return value;
    }
    
    public String[] splitChain(String chain,String splitCharacter){
        return chain.split(splitCharacter);
    }
    
    /*****
    *
    String[] to
    String from,
    String subject,
    String text,
    boolean htmlText, 
    String cfgIP,
    String port,
    Logger log, 
    String pdfPath,
    String pdfPathDupli,
    String user,
    final String pass
    *****
    */
    public void sendMail(String[] to,String from,String subject,String text,
            boolean htmlText, String cfgIP,String port,Logger log, 
            String pdfPath,String pdfPathDupli,String user,final String pass){
        try {
            
            final String userMail=user,passMail=pass;
            
            Properties properties = new Properties();//Define las propiedades
            properties.setProperty("mail.smtp.host", cfgIP);
            properties.setProperty("mail.smtp.starttls.enable", "true");
            properties.setProperty("mail.smtp.port",port);
            properties.setProperty("mail.smtp.user", from);
            properties.setProperty("mail.smtp.auth", "true");
            Session session = Session.getInstance(properties,
            new javax.mail.Authenticator() {
                protected PasswordAuthentication getPasswordAuthentication() {
                        return new PasswordAuthentication(userMail, passMail);
                }});//crea una nueva instancia de sesion en gmail en este caso con las propiedades
//            session.setDebug(true);
            
            MimeMultipart multPartMail = new MimeMultipart();
            String contentType="text/html";
            
            BodyPart header = new MimeBodyPart();
            header.setContent("Estimado(a):<br>",contentType);
            
            BodyPart textBody = new MimeBodyPart();
            
            if(!htmlText){
                textBody.setText(text);
            }else{
//                String charset ="utf-8";
                textBody.setContent(text, contentType);
            }
            
            BodyPart footer = new MimeBodyPart();
            footer.setContent("<br>Allware LTDA. - http://www.allware.cl.<br> "
                    + "Este mensaje fue generado automáticamente."
                    + "Se ruega no responder este email, ante cualquier duda"
                    + "contactarse con el área correspondiente.",contentType);
            
            //agregamos al mensage los contenidos
            multPartMail.addBodyPart(header);
            multPartMail.addBodyPart(textBody);
            multPartMail.addBodyPart(footer);
            
            if(pdfPath!=null){//agrega documento adjunto, null para no adjuntar
                BodyPart attached = new MimeBodyPart();
                FileDataSource dataSource = new FileDataSource(pdfPath);
                attached.setDataHandler(new DataHandler(dataSource));
                attached.setFileName(dataSource.getName());
                multPartMail.addBodyPart(attached);
            }
            if(pdfPathDupli!=null){//agrega documento adjunto, null para no adjuntar
                BodyPart attached = new MimeBodyPart();
                FileDataSource dataSource = new FileDataSource(pdfPathDupli);
                attached.setDataHandler(new DataHandler(dataSource));
                attached.setFileName(dataSource.getName());
                multPartMail.addBodyPart(attached);
            }
            
            MimeMessage message = new MimeMessage(session);
            message.setSubject("DTE-ALLWARE: "+subject);
            message.setFrom(new InternetAddress(from));
//            InternetAddress[] destinations = new InternetAddress[to.length];
            for (int i = 0; i < to.length; i++) {
                message.addRecipient(Message.RecipientType.TO, new InternetAddress(to[i]));
            }
            
            message.setContent(multPartMail);
            Transport.send(message);
            log.debug("Mail sended");
        } catch (AddressException ex) {
            log.error(ex);
        } catch (MessagingException ex) {
            log.error(ex);
        }
    }
    
    public EnvioBOLETADocument.EnvioBOLETA.SetDTE.Caratula setCaratulaTicket(EnvioBOLETADocument ticket,String recepS,String enviadorS,BOLETADefType doc){
        EnvioBOLETADocument.EnvioBOLETA.SetDTE.Caratula caratula = ticket.getEnvioBOLETA().getSetDTE().getCaratula();
        caratula.setRutReceptor(recepS);
        caratula.setRutEnvia(enviadorS);
        
        EnvioBOLETADocument.EnvioBOLETA.SetDTE.Caratula.SubTotDTE[] subt = new EnvioBOLETADocument.EnvioBOLETA.SetDTE.Caratula.SubTotDTE[1];
        
        EnvioBOLETADocument.EnvioBOLETA.SetDTE.Caratula.SubTotDTE sbdte= EnvioBOLETADocument.EnvioBOLETA.SetDTE.Caratula.SubTotDTE.Factory.newInstance();
        sbdte.setTpoDTE(doc.getDocumento().getEncabezado().getIdDoc()
        .getTipoDTE());
        int totalDte=1;
        sbdte.setNroDTE(new BigInteger(String.valueOf(totalDte)));
        
        subt[0]=sbdte;
        caratula.setSubTotDTEArray(subt);
        return caratula;
        
    }
    
    public BOLETADefType signTicket(BOLETADefType doc, Logger log, 
            XmlOptions opts, String certS,String passS,AutorizacionType caf,
            HashMap<String, String> namespaces) throws KeyStoreException, 
            IOException, NoSuchAlgorithmException, CertificateException, 
            UnrecoverableKeyException, TimbreException, SignatureException, 
            InvalidKeyException, NoSuchPaddingException, InvalidKeySpecException, 
            InvalidAlgorithmParameterException, XmlException, KeyException, 
            MarshalException, XMLSignatureException, SAXException, 
            ParserConfigurationException{
        
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream(certS), passS.toCharArray());
        String alias = ks.aliases().nextElement();
        log.debug("Function =[checkDTE] MSG=[1.- Usando certificado " + alias
                + " del archivo PKCS12: " + certS+"]");

        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
        PrivateKey key = (PrivateKey) ks.getKey(alias, passS.toCharArray());

        //doc.getDTE().getDocumento().getEncabezado().getIdDoc().setFolio(folio);
        // Timbro
        doc.timbrar(caf.getCAF(), caf.getPrivateKey(null));//aqui
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DATE,1);
        doc.getDocumento().setTmstFirma(cal);

        opts.setSavePrettyPrint();
        opts.setSavePrettyPrintIndent(0);
        opts.setCharacterEncoding("ISO-8859-1");
        opts.setSaveImplicitNamespaces(namespaces);

//        doc.save(new File("boeltaTemp.xml"),opts);
        // Releo formateado
        doc = BOLETADefType.Factory.parse(doc.newInputStream(opts), opts);

        // firmo
        doc.sign(key, cert);
        
        return doc;
    }
    
    public String generateTableHtml(int folio,String type,String emisor,String receptor,String trackId){
        String table = "<style type=\"text/css\">" +
                            ".tg  {border-collapse:collapse;border-spacing:0;}" +
                            ".tg td{font-family:Arial, sans-serif;font-size:14px;padding:10px 5px;border-style:solid;border-width:1px;overflow:hidden;word-break:normal;}" +
                            ".tg th{font-family:Arial, sans-serif;font-size:14px;font-weight:normal;padding:10px 5px;border-style:solid;border-width:1px;overflow:hidden;word-break:normal;}" +
                            "</style>" +
                            "<table class=\"tg\">" +
                            "  <tr>" +
                            "    <td class=\"tg-031e\">Folio</td>" +
                            "    <td class=\"tg-031e\">:</td>" +
                            "    <td class=\"tg-031e\">"+folio+"</td>" +
                            "  </tr>" +
                            "  <tr>" +
                            "    <td class=\"tg-031e\">Tipo</td>" +
                            "    <td class=\"tg-031e\">:</td>" +
                            "    <td class=\"tg-031e\">"+type+"</td>" +
                            "  </tr>" +
                            "  <tr>" +
                            "    <td class=\"tg-031e\">Rut Emisor</td>" +
                            "    <td class=\"tg-031e\">:</td>" +
                            "    <td class=\"tg-031e\">"+emisor+"</td>" +
                            "  </tr>" +
                            "  <tr>" +
                            "    <td class=\"tg-031e\">Rut Receptor</td>" +
                            "    <td class=\"tg-031e\">:</td>" +
                            "    <td class=\"tg-031e\">"+receptor+"</td>" +
                            "  </tr>" +
                            "  <tr>" +
                            "    <td class=\"tg-031e\">TrackId SII</td>" +
                            "    <td class=\"tg-031e\">:</td>" +
                            "    <td class=\"tg-031e\">"+trackId+"</td>" +
                            "  </tr>" +
                            "</table>";
        return table;
    }
    
    public void schemaValidation(String xml,String urlXSD, String baseUrl) throws ParserConfigurationException, SAXException, IOException{
//        try {
//            // parse an XML document into a DOM tree
//            DocumentBuilder parser = DocumentBuilderFactory.newInstance().newDocumentBuilder();
//            Document document = parser.parse(xml);
//
//            // create a SchemaFactory capable of understanding WXS schemas
//            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
//            // load a WXS schema, represented by a Schema instance
//            Source schemaFile = new StreamSource(new File(urlXSD));
//            Schema schema = factory.newSchema(schemaFile);
//
//            // create a Validator instance, which can be used to validate an instance document
//            Validator validator = schema.newValidator();
//
//            // validate the DOM tree
//
//            validator.validate(new StringReader(xml));
//        } catch (SAXException | IOException e) {
//            System.out.println(e);
//        }
        
        final Source schemaSource =
            new StreamSource(new File(urlXSD));
        final Schema schema =
            SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI).newSchema(schemaSource);

        //Creating a SAXParser for our input XML
        //First the factory
        final SAXParserFactory factory = SAXParserFactory.newInstance();
        //Must be namespace aware to receive element names
        factory.setNamespaceAware(true);
        //Setting the Schema for validation
        factory.setSchema(schema);
        //Now the parser itself
        final SAXParser parser = factory.newSAXParser();

        //Creating an instance of our special handler
        final MyContentHandler handler = new MyContentHandler();

        //Parsing
        parser.parse(new InputSource(new StringReader(xml)), handler);
    }
    
    private static class MyContentHandler extends DefaultHandler {

        private String element = "";

        public void startElement(String uri, String localName, String qName,
                Attributes attributes) throws SAXException {

            if(localName != null && !localName.isEmpty())
                element = localName;
            else
                element = qName;

        }

        public void warning(SAXParseException exception) throws SAXException {
            System.out.println(element + ": " + exception.getMessage());
        }

        public void error(SAXParseException exception) throws SAXException {
            System.out.println(element + ": " + exception.getMessage());
        }

        @Override
        public void fatalError(SAXParseException exception) throws SAXException {
            System.out.println(element + ": " + exception.getMessage());
        }

        public String getElement() {
            return element;
        }

    }
    
}


























