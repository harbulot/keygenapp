package net.bblfish.dev.foafssl.keygen.bouncy;

import net.bblfish.dev.foafssl.keygen.Certificate;
import net.bblfish.dev.foafssl.keygen.KeygenService;

import java.security.InvalidParameterException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A static class to deal with keygen requests
 * <p/>
 * The disadvantage of using it is that if it fails, it will probably need restarting
 * the whole container. The advantage is that one can get this going on non osgi frameworks
 * easily.
 * <p/>
 * If this class is never called it will never get loaded.
 *
 * @author Henry Story
 */
public class StaticKeygenService implements KeygenService {
	static Logger log = Logger.getLogger(StaticKeygenService.class.getName());
	static BouncyKeygenService keygenService;

	static {
		keygenService = new BouncyKeygenService();
		try {
			keygenService.initialize();
		} catch (Exception e) {
			log.log(Level.SEVERE, "Could not start static keygen service ", e);
		}
	}

	/**
	 * Create certificates from PEM requests, coming from Internet Explorer usually
	 *
	 * @param pemCsr
	 * @return A yet incomplete certificate
	 */
	public  Certificate createFromPEM(String pemCsr) {
		return keygenService.createFromPEM(pemCsr);
	}


	/**
	 * Create Certificates from SPKAC requests coming from the other browsers
	 *
	 * @param spkac
	 * @return an as yet incomplete Certificate
	 * @throws InvalidParameterException
	 */
	public  Certificate createFromSpkac(String spkac)  {
		return keygenService.createFromSpkac(spkac);
	}

    public  Certificate createFromCRMF(String crmfReq) {
        return keygenService.createFromCRMF(crmfReq);
    }

}
