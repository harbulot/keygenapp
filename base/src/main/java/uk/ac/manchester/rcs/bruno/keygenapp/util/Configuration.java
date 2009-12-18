/**

Copyright (c) 2008-2009, The University of Manchester, United Kingdom.
All rights reserved.

Redistribution and use in source and binary forms, with or without 
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice, 
      this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright 
      notice, this list of conditions and the following disclaimer in the 
      documentation and/or other materials provided with the distribution.
 * Neither the name of the The University of Manchester nor the names of 
      its contributors may be used to endorse or promote products derived 
      from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
POSSIBILITY OF SUCH DAMAGE.

  Author........: Bruno Harbulot
 
 */
package uk.ac.manchester.rcs.bruno.keygenapp.util;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Enumeration;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NameNotFoundException;
import javax.naming.NamingException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;

import org.bouncycastle.asn1.x509.X509Name;

/**
 * This class initialises the configuration of the "Mini CA" from servlet
 * parameters.
 * 
 * @author Bruno Harbulot.
 * 
 */
public class Configuration {
    public static final String KEYSTORE_JNDI_INITPARAM = "keystore";
    public static final String DEFAULT_KEYSTORE_JNDI_INITPARAM = "keystore/signingKeyStore";
    public static final String KEYSTORE_PATH_INITPARAM = "keystorePath";
    public static final String KEYSTORE_RESOURCE_PATH_INITPARAM = "keystoreResourcePath";
    public static final String KEYSTORE_TYPE_INITPARAM = "keystoreType";
    public static final String KEYSTORE_PASSWORD_INITPARAM = "keystorePassword";
    public static final String KEY_PASSWORD_INITPARAM = "keyPassword";
    public static final String ALIAS_INITPARAM = "keyAlias";

    public static final String ISSUER_NAME_INITPARAM = "issuerName";

    private PrivateKey caPrivKey;
    private PublicKey caPublicKey;

    private X509Name issuerName;

    private long certificateSerialNumber;

    public PrivateKey getCaPrivKey() {
        return this.caPrivKey;
    }

    public void setCaPrivKey(PrivateKey caPrivKey) {
        this.caPrivKey = caPrivKey;
    }

    public PublicKey getCaPublicKey() {
        return this.caPublicKey;
    }

    public void setCaPublicKey(PublicKey caPublicKey) {
        this.caPublicKey = caPublicKey;
    }

    public X509Name getIssuerName() {
        return this.issuerName;
    }

    public void setIssuerName(X509Name issuerName) {
        this.issuerName = issuerName;
    }

    public void setIssuerName(String issuerName) {
        this.issuerName = new X509Name(issuerName);
    }

    public synchronized long getCertificateSerialNumber() {
        return this.certificateSerialNumber;
    }

    public synchronized long nextCertificateSerialNumber() {
        this.certificateSerialNumber++;
        return this.certificateSerialNumber;
    }

    public synchronized void setCertificateSerialNumber(
            long certificateSerialNumber) {
        this.certificateSerialNumber = certificateSerialNumber;
    }

    /**
     * Initialises the servlet: loads the keystore/keys to use to sign the
     * assertions and the issuer name.
     */
    public void init(HttpServlet servlet) throws ServletException {

        KeyStore keyStore = null;

        String keystoreJdniName = servlet
                .getInitParameter(KEYSTORE_JNDI_INITPARAM);
        if (keystoreJdniName == null) {
            keystoreJdniName = DEFAULT_KEYSTORE_JNDI_INITPARAM;
        }
        String keystorePath = servlet.getInitParameter(KEYSTORE_PATH_INITPARAM);
        String keystoreResourcePath = servlet
                .getInitParameter(KEYSTORE_RESOURCE_PATH_INITPARAM);
        String keystoreType = servlet.getInitParameter(KEYSTORE_TYPE_INITPARAM);
        String keystorePassword = servlet
                .getInitParameter(KEYSTORE_PASSWORD_INITPARAM);
        String keyPassword = servlet.getInitParameter(KEY_PASSWORD_INITPARAM);
        if (keyPassword == null)
            keyPassword = keystorePassword;
        String alias = servlet.getInitParameter(ALIAS_INITPARAM);
        String issuerName = servlet.getInitParameter(ISSUER_NAME_INITPARAM);

        try {
            Context ctx = new InitialContext();
            try {
                keyStore = (KeyStore) ctx.lookup("java:comp/env/"
                        + keystoreJdniName);
            } finally {
                if (ctx != null) {
                    ctx.close();
                }
            }
        } catch (NameNotFoundException e) {
        } catch (NamingException e) {
            throw new ServletException(e);
        }
        if (keyStore == null) {
            try {
                InputStream ksInputStream = null;

                try {
                    if (keystorePath != null) {
                        ksInputStream = new FileInputStream(keystorePath);
                    } else if (keystoreResourcePath != null) {
                        ksInputStream = Configuration.class
                                .getResourceAsStream(keystoreResourcePath);
                    }
                    keyStore = KeyStore
                            .getInstance((keystoreType != null) ? keystoreType
                                    : KeyStore.getDefaultType());
                    keyStore.load(ksInputStream,
                            keystorePassword != null ? keystorePassword
                                    .toCharArray() : null);
                } finally {
                    if (ksInputStream != null) {
                        ksInputStream.close();
                    }
                }
            } catch (FileNotFoundException e) {
                throw new ServletException("Could not load keystore: " + e);
            } catch (KeyStoreException e) {
                throw new ServletException("Could not load keystore: " + e);
            } catch (NoSuchAlgorithmException e) {
                throw new ServletException("Could not load keystore: " + e);
            } catch (CertificateException e) {
                throw new ServletException("Could not load keystore: " + e);
            } catch (IOException e) {
                throw new ServletException("Could not load keystore: " + e);
            }
        }

        try {
            if (alias == null) {
                Enumeration<String> aliases = keyStore.aliases();
                while (aliases.hasMoreElements()) {
                    String tempAlias = aliases.nextElement();
                    if (keyStore.isKeyEntry(tempAlias)) {
                        alias = tempAlias;
                        break;
                    }
                }
            }
            if (alias == null) {
                throw new ServletException(
                        "Invalid keystore configuration: alias unspecified or couldn't find the alias.");
            }

            PublicKey publicKey = keyStore.getCertificate(alias).getPublicKey();
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias,
                    keyPassword != null ? keyPassword.toCharArray() : null);

            setIssuerName(issuerName);
            setCaPrivKey(privateKey);
            setCaPublicKey(publicKey);
        } catch (UnrecoverableKeyException e) {
            throw new ServletException("Could not load keystore.");
        } catch (KeyStoreException e) {
            throw new ServletException("Could not load keystore.");
        } catch (NoSuchAlgorithmException e) {
            throw new ServletException("Could not load keystore.");
        }
    }
}
