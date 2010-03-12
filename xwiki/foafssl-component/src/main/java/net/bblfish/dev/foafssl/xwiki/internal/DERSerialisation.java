package net.bblfish.dev.foafssl.xwiki.internal;

import net.bblfish.dev.foafssl.xwiki.Certificate;
import org.bouncycastle.openssl.PEMWriter;

import java.io.IOException;
import java.io.StringWriter;
import java.security.cert.CertificateEncodingException;

/**
 * A DER serialisation of a certificate
 * This is the one that Safari, Firefox and Opera understand out of the box
 *
 * @Date: Mar 12, 2010
 * @author Henry Story
 */
public class DERSerialisation extends DefaultCertSerialisation {
    byte[] ser = null;

    DERSerialisation(Certificate cer) {
        super(cer);
    }

    @Override
    protected byte[] getSerialization() {
        if (ser == null) {
            try {
                ser = cer.getCertificate().getEncoded();
            } catch (CertificateEncodingException e) {
                getLogger().error("could not DER encode the give certificate.");
            }
        }
        return ser;
    }

    public String getMimeType() {
        return "application/x-x509-user-cert";
    }
}