package net.bblfish.dev.foafssl.keygen.bouncy;

import net.bblfish.dev.foafssl.keygen.Certificate;

import java.security.InvalidParameterException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A static class to deal with keygen requests
 *
 * The disadvantage of using it is that if it fails, it will probably need restarting
 * the whole container. The advantage is that one can get this going on non osgi frameworks
 * easily.
 *
 * If this class is never called it will never get loaded.
 *
 * @author Henry Story
 */
public class StaticKeygenService {
    static Logger log = Logger.getLogger(StaticKeygenService.class.getName());
    static KeygenService keygenService;
    static {
       keygenService = new KeygenService();
        try {
            keygenService.initialize();
        } catch (Exception e) {
            log.log(Level.SEVERE,"Could not start static keygen service ",e);
        }
    }

    /**
     * Create certificates from PEM requests, coming from Internet Explorer usually
     * @param pemCsr
     * @return A yet incomplete certificate
     */
    public static Certificate createFromPEM(String pemCsr) {
        return keygenService.createFromPEM(pemCsr);
    }


    /**
     * Create Certificates from SPKAC requests coming from the other browsers
     * @param spkac
     * @return an as yet incomplete Certificate
     * @throws InvalidParameterException
     */
    public static Certificate createFromSpkac(String spkac) throws InvalidParameterException {
        return keygenService.createFromSpkac(spkac);
    }

}
