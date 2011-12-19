package es.gob.afirma.keystores.filters;

import java.io.File;
import java.security.InvalidKeyException;

import org.junit.Assert;
import org.junit.Test;

import es.gob.afirma.keystores.main.callbacks.CachePasswordCallback;
import es.gob.afirma.keystores.main.common.AOKeyStore;
import es.gob.afirma.keystores.main.common.AOKeyStoreManager;
import es.gob.afirma.keystores.main.common.AOKeyStoreManagerFactory;
import es.gob.afirma.keystores.main.common.AOKeystoreAlternativeException;
import es.gob.afirma.miniapplet.keystores.filters.SSLFilter;

/**
 * Prueba el filtrado de certificado a partir de un numero de serie en hexadecimal. No prueba la
 * condicion de, si se indica el numero de serie del certificado de autenticacion de un DNIe
 * se seleccione en lugar el certificado de firma de ese DNIe. 
 */
public class SSLFilterTest {

	private static final AOKeyStore KEYSTORE_TYPE = AOKeyStore.PKCS12;
    private static final String CERT_PATH = "src" + File.separator + "test" + File.separator + "resources" + File.separator + "ANF_PF_Activo.pfx"; //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
    private static final String CERT_PASS = "12341234"; //$NON-NLS-1$
    private static final String CERT_SN = "03 ea"; //$NON-NLS-1$
    
    private static final String CERT_ALIAS = "anf usuario activo"; //$NON-NLS-1$
	
	/**
	 * Comprobaci&oacute;n del filtrado.
	 * @throws InvalidKeyException Clave no v&aacute;lida.
	 * @throws AOKeystoreAlternativeException Cuando no se puede abrir el almacen de claves.
	 */
	@Test
	public void match() throws InvalidKeyException, AOKeystoreAlternativeException {
		
		SSLFilter filter = new SSLFilter(CERT_SN);
		
		System.out.println(new File(CERT_PATH).getAbsolutePath());
		
		AOKeyStoreManager manager = 
			AOKeyStoreManagerFactory.getAOKeyStoreManager(
					KEYSTORE_TYPE,
					new File(CERT_PATH).getAbsolutePath(),
					"TEST", //$NON-NLS-1$
					new CachePasswordCallback(CERT_PASS.toCharArray()),
					null);

		System.out.println("Alias filtrados:"); //$NON-NLS-1$
		for (String alias : filter.matches(manager.getAliases(), manager)) {
			System.out.println(alias);
			Assert.assertEquals("El certificado recuperado no es el esperado", CERT_ALIAS, alias); //$NON-NLS-1$
		}
	}
}