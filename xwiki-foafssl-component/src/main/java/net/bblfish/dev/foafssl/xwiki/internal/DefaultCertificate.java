/*
 * New BSD license: http://opensource.org/licenses/bsd-license.php
 *
 * Copyright (c) 2010.
 * Henry Story
 * http://bblfish.net/
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *  - Neither the name of bblfish.net nor the names of its contributors
 *   may be used to endorse or promote products derived from this software
 *   without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

package net.bblfish.dev.foafssl.xwiki.internal;

import net.bblfish.dev.foafssl.xwiki.CertSerialisation;
import net.bblfish.dev.foafssl.xwiki.Certificate;
import net.bblfish.dev.foafssl.xwiki.PubKey;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.misc.NetscapeCertType;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;
import org.xwiki.component.logging.AbstractLogEnabled;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Vector;

/**
 * Default implementation of Certificate
 * User: hjs
 * Date: Feb 14, 2010
 * Time: 7:46:30 PM
 */

public class DefaultCertificate extends AbstractLogEnabled implements Certificate {
    String webId;
    String CN;
    Date startDate;
    Date endDate;
    int durationInDays;
    float durationInHours;
    PubKey subjectPubKey;
    private CertificateScriptService service;
    X509Certificate cert = null;

    DefaultCertificate(CertificateScriptService service) {
        this.service = service;
    }

    public void setSubjectWebID(String urlStr) {
        try {
            URL url = new URL(urlStr);
            String protocol = url.getProtocol();
            if (protocol.equals("http") || protocol.equals("https") || protocol.equals("ftp") || protocol.equals("ftps")) {
                //everything probably ok, though really https should be the default
            } else {
                //could very well be a mistake
                getLogger().warn("using WebId with protocol " + protocol + ". Could be a mistake. WebId=" + url);
            }

        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
        this.webId = urlStr;
    }

    public void setSubjectCommonName(String name) {
        CN = name;
    }

    public void setStartDate(Date startDate) {
        this.startDate = startDate;
    }

    public void setEndDate(Date endDate) {
        this.endDate = endDate;
    }


    public void setDurationInDays(int days) {
        this.durationInDays = days;
    }

    public void setDurationInHours(float hours) {
        this.durationInHours = hours;
    }

    public PubKey getSubjectPublicKey() {
        return subjectPubKey;
    }

    /**
     * Set the <a href="http://en.wikipedia.org/wiki/Spkac">Spkac</a> data sent by browser
     * One should set either this or the pemCSR.
     *
     * @param pubkey the public key for the subject
     */
    void setSubjectPublicKey(PubKey pubkey) {
        this.subjectPubKey = pubkey;
    }

    CertSerialisation sz=null;
    public CertSerialisation getSerialisation() throws Exception {
        System.out.println("in getSerialisation");
        if (cert == null) {
            generate();
        }
        if (sz==null) {
            sz = new DefaultCertSerialisation(cert.getEncoded());
        }
        System.out.println("returning a serialisation");
        return sz;
    }

    protected void generate() throws Exception {
        System.out.println("in generate");
        X509V3CertificateGenerator certGenerator = new X509V3CertificateGenerator();

        certGenerator.reset();
        /*
         * Sets up the subject distinguished name. Since it's a self-signed
         * certificate, issuer and subject are the same.
         */
        certGenerator.setIssuerDN(new X509Name(service.issuer));


        Vector<DERObjectIdentifier> subjectDnOids = new Vector<DERObjectIdentifier>();
        Vector<String> subjectDnValues = new Vector<String>();

        subjectDnOids.add(X509Name.O);
        subjectDnValues.add("FOAF+SSL");
        subjectDnOids.add(X509Name.UID);
        subjectDnValues.add(webId);
        subjectDnOids.add(X509Name.CN);
        subjectDnValues.add(CN);

        X509Name DName = new X509Name(subjectDnOids, subjectDnValues);
        certGenerator.setSubjectDN(DName);

        /*
         * Sets up the validity dates.
         */
        certGenerator.setNotBefore(getStartDate());

        certGenerator.setNotAfter(getEndDate());

        /*
         * The serial-number of this certificate is 1. It makes sense because
         * it's self-signed.
         */
        certGenerator.setSerialNumber(service.nextRandom());

        /*
         * Sets the public-key to embed in this certificate.
         */
        certGenerator.setPublicKey(getSubjectPublicKey().getPublicKey());
        /*
         * Sets the signature algorithm.
         */
//        String pubKeyAlgorithm = service.caPubKey.getAlgorithm();
//        if (pubKeyAlgorithm.equals("DSA")) {
//            certGenerator.setSignatureAlgorithm("SHA1WithDSA");
//        } else if (pubKeyAlgorithm.equals("RSA")) {
        certGenerator.setSignatureAlgorithm("SHA1WithRSAEncryption");
//        } else {
//            RuntimeException re = new RuntimeException(
//                    "Algorithm not recognised: " + pubKeyAlgorithm);
//            LOGGER.error(re.getMessage(), re);
//            throw re;
//        }

        /*
         * Adds the Basic Constraint (CA: false) extension.
         */
        certGenerator.addExtension(X509Extensions.BasicConstraints, true,
                new BasicConstraints(false));

        /*
         * Adds the Key Usage extension.
         */
        certGenerator.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(
                KeyUsage.digitalSignature | KeyUsage.nonRepudiation
                        | KeyUsage.keyEncipherment | KeyUsage.keyAgreement
                        | KeyUsage.keyCertSign));

        /*
         * Adds the Netscape certificate type extension.
         */
        certGenerator.addExtension(MiscObjectIdentifiers.netscapeCertType,
                false, new NetscapeCertType(NetscapeCertType.sslClient
                        | NetscapeCertType.smime));

        /*
         * Adds the authority key identifier extension.
         */
        AuthorityKeyIdentifierStructure authorityKeyIdentifier;
        try {
            authorityKeyIdentifier = new AuthorityKeyIdentifierStructure(
                    getSubjectPublicKey().getPublicKey());
        } catch (InvalidKeyException e) {
            throw new Exception("failed to parse CA cert. This should never happen", e);
        }

        certGenerator.addExtension(X509Extensions.AuthorityKeyIdentifier,
                false, authorityKeyIdentifier);

        /*
         * Adds the subject key identifier extension.
         */
        SubjectKeyIdentifier subjectKeyIdentifier = new SubjectKeyIdentifierStructure(
                getSubjectPublicKey().getPublicKey());
        certGenerator.addExtension(X509Extensions.SubjectKeyIdentifier, false,
                subjectKeyIdentifier);

        /*
         * Adds the subject alternative-name extension (critical).
         */
        if (webId != null) {
            GeneralNames subjectAltNames = new GeneralNames(new GeneralName(
                    GeneralName.uniformResourceIdentifier, webId));
            certGenerator.addExtension(X509Extensions.SubjectAlternativeName,
                    true, subjectAltNames);
        } else throw new Exception("WebId not set!");

        /*
         * Creates and sign this certificate with the private key corresponding
         * to the public key of the FOAF+SSL DN
         */
        cert = certGenerator.generate(service.privateKey);

        /*
         * Checks that this certificate has indeed been correctly signed.
         */
        cert.verify(service.certificate.getPublicKey());
        System.out.println("exit generate");

    }

    private Date getEndDate() {
        if (endDate == null) {
            long endtime;
            if (durationInDays != 0 || durationInHours != 0) {
                endtime = getStartDate().getTime();
                endtime += durationInDays * 24 * 60 * 60 * 1000 + (long) (durationInHours * 60 * 60 * 1000);
            } else {
                endtime = startDate.getTime() + 365L * 24L * 60L * 60L * 1000L;
            }
            endDate = new Date(endtime);
        }
        return endDate;
    }


    public Date getStartDate() {
        if (startDate == null) {
            startDate = new Date();
        }
        return startDate;
    }

}
