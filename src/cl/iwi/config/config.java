/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cl.iwi.config;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author dgonzalezj
 */
public class config {
    Properties prop = new Properties();
    
    /**
     * String path properties file, this value by default
     */
    String propFileName = "resources/config.properties";
    
    
    public String getValues(String variableName) throws IOException{
        InputStream inputStream = null;
        try{
            
            if (variableName == null){
                throw new IllegalArgumentException("variable name not found");
            }
            inputStream = getClass().getClassLoader().getResourceAsStream(propFileName);

            if (inputStream != null) {
                prop.load(inputStream);
            } else {
                throw new FileNotFoundException("property file '" + propFileName + "' not found in the classpath");
            }
        
            return prop.getProperty(variableName);
        }catch(FileNotFoundException ex){
            Logger.getLogger(config.class.getName()).log(Level.SEVERE, null, ex);
        }
        finally {
                inputStream.close();
        }
        return null;
    }

    public String getPropFileName() {
        return propFileName;
    }

    public void setPropFileName(String propFileName) {
        this.propFileName = propFileName;
    }
    
    
}
