/* Copyright (C) 2011 [Gobierno de Espana]
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 * Date: 11/01/11
 * You may contact the copyright holder at: soporte.afirma5@mpt.es
 */

/**
 * copied from es.gob.afirma.signature
 */

package ingent;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CRLException;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.logging.Logger;

import javax.help.UnsupportedOperationException;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;

import es.gob.afirma.core.signers.AOSigner;
import ingent.SignValidity.SIGN_DETAIL_TYPE;
import ingent.SignValidity.VALIDITY_ERROR;
import es.gob.afirma.signers.cades.AOCAdESSigner;
import es.gob.afirma.signers.cms.AOCMSSigner;

/** Validador de firmas binarias.
 * @author Carlos Gamuci
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class ValidateBinarySignature {

	private ValidateBinarySignature() {
		// No permitimos la instanciacion
	}

    /** Valida una firma binaria (CMS/CAdES). Si se especifican los datos que se firmaron
     * se comprobar&aacute; que efectivamente fueron estos, mientras que si no se indican
     * se extraer&aacute;n de la propia firma. Si la firma no contiene los datos no se realizara
     * esta comprobaci&oacute;n.
     * @param sign Firma binaria
     * @param data Datos firmados o {@code null} si se desea comprobar contra los datos incrustados
     * en la firma.
     * @return <code>true</code> si la firma es v&aacute;lida, <code>false</code> en caso contrario
     * @throws IOException Cuando ocurre algun error durante la lectura de los datos.
     */
    public static SignValidity validate(final byte[] sign, final byte[] data) throws IOException {
        if (sign == null) {
            throw new IllegalArgumentException("La firma a validar no puede ser nula"); //$NON-NLS-1$
        }

        AOSigner signer = new AOCAdESSigner();
        if (!signer.isSign(sign)) {
            signer = new AOCMSSigner();
            if (!signer.isSign(sign)) {
                return new SignValidity(SIGN_DETAIL_TYPE.KO, null);
            }
        }

        try {
        	verifySignatures(sign, data);
        }
        catch (final CertStoreException e) {
            // Error al recuperar los certificados o estos no son validos
            return new SignValidity(SIGN_DETAIL_TYPE.KO, VALIDITY_ERROR.CERTIFICATE_PROBLEM);
        }
        catch (final CertificateExpiredException e) {
            // Certificado caducado
            return new SignValidity(SIGN_DETAIL_TYPE.KO, VALIDITY_ERROR.CERTIFICATE_EXPIRED);
        }
        catch (final CertificateNotYetValidException e) {
            // Certificado aun no valido
            return new SignValidity(SIGN_DETAIL_TYPE.KO, VALIDITY_ERROR.CERTIFICATE_NOT_VALID_YET);
        }
        catch (final NoSuchAlgorithmException e) {
            // Algoritmo no reconocido
            return new SignValidity(SIGN_DETAIL_TYPE.KO, VALIDITY_ERROR.ALGORITHM_NOT_SUPPORTED);
        }
        catch (final NoMatchDataException e) {
            // Los datos indicados no coinciden con los datos de firma
            return new SignValidity(SIGN_DETAIL_TYPE.KO, VALIDITY_ERROR.NO_MATCH_DATA);
        }
        catch (final CRLException e) {
            // Problema en la validacion de las CRLs de la firma
            return new SignValidity(SIGN_DETAIL_TYPE.KO, VALIDITY_ERROR.CRL_PROBLEM);
        }
        catch (final IOException e) {
        	throw e;
		}
        catch (final Exception e) {
            Logger.getLogger("es.gob.afirma").info("Los datos no son una firma binaria valida: " + e); //$NON-NLS-1$ //$NON-NLS-2$
            return new SignValidity(SIGN_DETAIL_TYPE.KO, null);
        }

        return new SignValidity(SIGN_DETAIL_TYPE.OK, null);
    }

    /** Verifica la valides de una firma. Si la firma es v&aacute;lida, no hace nada. Si no es
     * v&aacute;lida, lanza una excepci&oacute;n.
     * @param sign Firma que se desea validar.
     * @param data Datos para la comprobaci&oacute;n.
     * @throws CMSException Cuando la firma no tenga una estructura v&aacute;lida.
     * @throws CertStoreException Cuando se encuentra un error en los certificados de
     * firma o estos no pueden recuperarse.
     * @throws CertificateExpiredException Cuando el certificado est&aacute;a caducado.
     * @throws CertificateNotYetValidException Cuando el certificado aun no es v&aacute;lido.
     * @throws NoSuchAlgorithmException Cuando no se reconoce o soporta alguno de los
     * algoritmos utilizados en la firma.
     * @throws NoMatchDataException Cuando los datos introducidos no coinciden con los firmados.
     * @throws CRLException Cuando ocurre un error con las CRL de la firma.
     * @throws NoSuchProviderException Cuando no se encuentran los proveedores de seguridad necesarios para validar la firma
     * @throws IOException Cuando no se puede crear un certificado desde la firma para validarlo
     * @throws OperatorCreationException Cuando no se puede crear el validado de contenido de firma*/
    private static void verifySignatures(final byte[] sign, final byte[] data) throws CMSException,
                                                                                      CertStoreException,
                                                                                      NoSuchAlgorithmException,
                                                                                      NoMatchDataException,
                                                                                      CRLException,
                                                                                      NoSuchProviderException,
                                                                                      CertificateException,
                                                                                      IOException,
                                                                                      OperatorCreationException {

        final CMSSignedData s;
        if (data == null) {
        	s = new CMSSignedData(sign);
        }
        else {
        	s = new CMSSignedData(new CMSProcessableByteArray(data), sign);
        }
        final Store store = s.getCertificates();

        final CertificateFactory certFactory = CertificateFactory.getInstance("X.509"); //$NON-NLS-1$

        for (final Object si : s.getSignerInfos().getSigners()) {
        	final SignerInformation signer = (SignerInformation) si;

            final Iterator<X509CertificateHolder> certIt = store.getMatches(new CertHolderBySignerIdSelector(signer.getSID())).iterator();
            final X509Certificate cert = (X509Certificate) certFactory.generateCertificate(
        		new ByteArrayInputStream(
    				certIt.next().getEncoded()
				)
    		);

            if (!signer.verify(new SignerInformationVerifier(
            	new	DefaultCMSSignatureAlgorithmNameGenerator(),
            	new DefaultSignatureAlgorithmIdentifierFinder(),
        		new JcaContentVerifierProviderBuilder().setProvider(new BouncyCastleProvider()).build(cert),
        		new BcDigestCalculatorProvider()
    		))) {
            	throw new CMSException("Firma no valida"); //$NON-NLS-1$
            }

        }

    }

    private static final class CertHolderBySignerIdSelector implements Selector {

    	private final SignerId signerId;
    	CertHolderBySignerIdSelector(final SignerId sid) {
    		if (sid == null) {
    			throw new IllegalArgumentException("El ID del firmante no puede ser nulo"); //$NON-NLS-1$
    		}
    		this.signerId = sid;
    	}

    	/** {@inheritDoc} */
		@Override
		public boolean match(final Object o) {
			if (!(o instanceof X509CertificateHolder)) {
				return false;
			}
			return CertHolderBySignerIdSelector.this.signerId.getSerialNumber().equals(((X509CertificateHolder)o).getSerialNumber());
		}

		/** {@inheritDoc} */
		@Override
		public Object clone() {
			throw new UnsupportedOperationException();
		}

    }
}
