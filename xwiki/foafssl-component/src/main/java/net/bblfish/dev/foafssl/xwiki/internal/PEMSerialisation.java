package net.bblfish.dev.foafssl.xwiki.internal;

import net.bblfish.dev.foafssl.xwiki.Certificate;
import org.bouncycastle.openssl.PEMWriter;

import java.io.IOException;
import java.io.StringWriter;

/**
 * PEM serialisation of a certificate
 *
 * This is a base64 encoding of a DER encoding of a certificate. It is delimited like this:
 *
 *  -----BEGIN CERTIFICATE-----
 *   base64 of DER
 *  ----END ... ----- 
 *
 * @Date: Mar 12, 2010
 * @author Henry Story
 */
public class PEMSerialisation extends DefaultCertSerialisation {
    byte[] ser = null;

    PEMSerialisation(Certificate cer) {
        super(cer);
    }

    @Override
    protected byte[] getSerialization() {
        if (ser == null) {
            try {
                StringWriter sw = new StringWriter();
                PEMWriter pemWriter = new PEMWriter(sw);
                pemWriter.writeObject(cer.getCertificate());
                pemWriter.close();
                ser = sw.toString().getBytes("UTF-8");
            } catch (IOException e) {
               getLogger().error("could not write PEM Serialisation");
            }
        }
        return ser;
    }

    public String getMimeType() {
        return "application/x-pem-file";
    }
}
