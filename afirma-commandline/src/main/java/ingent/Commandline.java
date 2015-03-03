/*
 * Use afirma from command line.
 */
package ingent;

import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.core.signers.AOSignConstants;
import es.gob.afirma.core.signers.AOSigner;
import es.gob.afirma.core.signers.AOSignerFactory;
import java.io.File;
import ingent.SignValidity.SIGN_DETAIL_TYPE;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;
import es.gob.afirma.keystores.AOKeyStore;
import es.gob.afirma.keystores.AOKeyStoreManager;
import es.gob.afirma.keystores.AOKeyStoreManagerFactory;
import es.gob.afirma.signers.xades.EFacturaAlreadySignedException;
import es.gob.afirma.signers.xades.InvalidEFacturaDataException;
import es.gob.afirma.signers.xml.InvalidXMLException;
import java.io.FileOutputStream;
import java.security.KeyStore.PrivateKeyEntry;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;


/**import es.gob.afirma.core.AOException;
 *
 * @author ingent
 */
public final class Commandline {
    
    public static void main(final String[] args) {
        if (args.length < 1) {
            usage();
            System.exit(-5);
        }
        if (System.getProperty("java.version").compareTo("1.6.0_18") < 0) {
            System.out.println("Wrong Java version");
            System.exit(-5);
        }
        System.out.println("Commandline version for afirma");
        if ("validate".equals(args[0])) {
            checkArgs(args, 2);
            if (!hasValidSignature(args[1])) {
                System.exit(1);
            }
        } else if ("sign".equals(args[0])) {
	    checkArgs(args, 4);
            if (!sign(args[1],args[2],args[3])) {
	      System.exit(1);
	    }
        } else {
            usage();
            System.exit(-5);
        }
        
    }
    
    public static boolean hasValidSignature(final String filePath) {
        
        final File signFile = new File(filePath);
        if (!signFile.exists() || !signFile.isFile()) {
            System.out.println("File does not exist: " + filePath);
            return false;
        }
        if (!signFile.canRead()) {
            System.out.println("File is not readable: " + filePath);
            return false;
        }

        final byte[] sign = null;
        final byte[] file = loadFile(signFile);
        SignValidity validity = new SignValidity(SIGN_DETAIL_TYPE.UNKNOWN, null);
        if (signFile != null) {
            try {
                validity = validateSign(file, sign);
            } catch (final Exception e) {
                System.out.println(e);
                validity = new SignValidity(SIGN_DETAIL_TYPE.KO, null);
            }
        }
        if (validity.getValidity() != SIGN_DETAIL_TYPE.OK) {
            System.out.println(validity.getError());
        }
        if (validity.getValidity() == SIGN_DETAIL_TYPE.OK) {
            System.out.println("Signature is valid");
            return true;
        } else {
            System.out.println("Signature is NOT valid");
            return false;
        }
    }

    /**
     * Recupera el contenido de un fichero.
     * @param file Fichero.
     * @return Datos contenidos en el fichero o {@code null} si ocurri&oacute; alg&uacute;n error.
     */
    static byte[] loadFile(final File file) {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(file);
            return AOUtil.getDataFromInputStream(fis);

        }
        catch(final OutOfMemoryError e) {
            System.out.println("Out of memory: " + e);
            return null;
        }
        catch (final Exception e) {
            System.out.println("No se ha podido cargar el fichero: " + e);
            return null;
        }
        finally {
            if (fis != null) {
                try { fis.close(); } catch (final Exception e) { /* Ignoramos los errores */ }
            }
        }
    }

    /**
     * Comprueba la validez de la firma.
     * @param sign Firma que se desea comprobar.
     * @return {@code true} si la firma es v&acute;lida, {@code false} en caso contrario.
     * @throws IOException Cuando ocurre algun error durante la lectura de los datos.
     * @throws Exception Cuando los datos introducidos no se corresponden con una firma.
     */
    private static SignValidity validateSign(final byte[] sign, final byte[] data) throws IOException {
        if (DataAnalizerUtil.isSignedPDF(sign)) {
            //TODO: aixo realment valida la signatura ???
            return new SignValidity(SIGN_DETAIL_TYPE.OK, null);
        }
        else if (DataAnalizerUtil.isSignedInvoice(sign)) { // Factura electronica
            return ValidateXMLSignature.validate(sign);
        }
        else if (DataAnalizerUtil.isSignedXML(sign)) {
            return ValidateXMLSignature.validate(sign);
        }
        else if(DataAnalizerUtil.isSignedBinary(sign)) {
            return ValidateBinarySignature.validate(sign, data);
        }
        else if (DataAnalizerUtil.isSignedODF(sign)) {
            //TODO: aixo realment valida la signatura ???
            return new SignValidity(SIGN_DETAIL_TYPE.OK, null);
        }
        else if (DataAnalizerUtil.isSignedOOXML(sign)) {
            //TODO: aixo realment valida la signatura ???
            return new SignValidity(SIGN_DETAIL_TYPE.OK, null);
        }
        return new SignValidity(SIGN_DETAIL_TYPE.KO, null);
    }

    /** Firma el fichero seleccionado
     *  asumimos que es un facturae
     */
  public static boolean sign(final String filePath, final String keysPath, final String certPass) {
		
	  final File signFile = new File(filePath);
	  if (!signFile.exists() || !signFile.isFile()) {
		  System.out.println("File does not exist: " + filePath);
		  return false;
	  }
	  if (!signFile.canRead()) {
		  System.out.println("File is not readable: " + filePath);
		  return false;
	  }
	  
	  final byte[] fileData = loadFile(signFile);
	  
	  // Password
	  myPasswordCallback scbh = new myPasswordCallback(certPass);
	  
	  // Keystore
	  final AOKeyStoreManager keyStoreManager;
	  try {
		  keyStoreManager = AOKeyStoreManagerFactory.getAOKeyStoreManager(AOKeyStore.PKCS12, keysPath, "PKCS#12 / PFX", scbh, null);
	  } catch (final Exception e) {
		  System.out.println("Error al abrir el certificado: " + e);
		  return false;
	  }
	  
	  // Just use first alias
	  String alias = keyStoreManager.getAliases()[0];
	  
	  final PrivateKeyEntry privateKeyEntry;
	  try {
		  privateKeyEntry = keyStoreManager.getKeyEntry(alias, scbh);
	  } catch (final Exception e) {
		  System.out.println("Error la llave privada: " + e);
		  return false;
	  }
	  // Properties
	  final Properties prop = new Properties();
	  prop.setProperty("format", AOSignConstants.SIGN_FORMAT_XADES_ENVELOPED);
	  prop.setProperty("mode", AOSignConstants.SIGN_MODE_IMPLICIT);
	  prop.setProperty("uri", "file://" + keysPath);

	  // Datos a firmar
	  final AOSigner signer;
	  signer = AOSignerFactory.getSigner(AOSignConstants.SIGN_FORMAT_FACTURAE);
	  
	  final byte[] signedData;
	  try {
		  signedData = signer.sign(fileData, "SHA1withRSA", privateKeyEntry.getPrivateKey(),privateKeyEntry.getCertificateChain(), prop);
	  } catch (final InvalidEFacturaDataException e) {
		  System.out.println("Se ha enviado a firmar como E-Factura datos que no son una factura electronica: " + e);
		  return false;
	  } catch (final EFacturaAlreadySignedException e) {
		  System.out.println("La factura ya tiene una firma electronica y no admite firmas adicionales: " + e);
		  return false;
	  } catch (final InvalidXMLException e) {
		  System.out.println("Se ha enviado a firmar con XAdES/XMLDSig Enveloped datos que no son un documento XML: " + e);
		  return false;
	  } catch (final Exception e) {
		  System.out.println("Error al generar la firma electronica: " + e);
		  return false;
	  }

	  // Si el proceso de firma devuelve una firma nula o vacia, lanzamos una excepcion
	  if (signedData == null || signedData.length == 0) {
		  System.out.println("La firma generada esta vacia");
		  return false;
	  }

	  try {
		  String outPath = FilenameUtils.removeExtension(filePath);
		  FileOutputStream output = new FileOutputStream(new File(outPath+".xsig"));
		  IOUtils.write(signedData, output);
	  } catch (final Exception e) {
		  System.out.println("Error al guardar el fichero firmado: " + e);
		  return false;
	  }
          
	  return true;
  }	
	
    
    private static void usage() {
        System.out.println("Usage: Commandline validate <file>");
        System.out.println("       Commandline sign <file> <pkcs12> [pkcs12_password]");
    }

    private static void checkArgs(String[] args, int size) {
        if (args.length != size) {
            usage();
            System.exit(-5);
        }
    }
}
