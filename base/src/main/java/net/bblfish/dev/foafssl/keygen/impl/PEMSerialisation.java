package net.bblfish.dev.foafssl.keygen.impl;

import net.bblfish.dev.foafssl.keygen.Certificate;
import org.bouncycastle.openssl.PEMWriter;

import java.io.IOException;
import java.io.StringWriter;
import java.util.logging.Level;
import java.util.logging.Logger;

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
    final Logger log = Logger.getLogger(DERSerialisation.class.getName());

    PEMSerialisation(Certificate cer) {
        super(cer);
    }

    @Override
    public byte[] getContent() {
        if (ser == null) {
            try {
                StringWriter sw = new StringWriter();
                PEMWriter pemWriter = new PEMWriter(sw);
                pemWriter.writeObject(cer.getCertificate());
                pemWriter.close();
                ser = sw.toString().getBytes("UTF-8");
            } catch (IOException e) {
               log.log(Level.SEVERE,"could not write PEM Serialisation");
            }
        }
        return ser;
    }


    public String getMimeType() {
        return "application/x-pem-file";
    }

}
