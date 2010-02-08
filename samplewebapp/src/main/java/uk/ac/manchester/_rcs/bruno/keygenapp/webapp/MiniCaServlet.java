/**

Copyright (c) 2008-2010, The University of Manchester, United Kingdom.
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
package uk.ac.manchester._rcs.bruno.keygenapp.webapp;

import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.openssl.PEMWriter;

import uk.ac.manchester._rcs.bruno.keygenapp.base.Configuration;
import uk.ac.manchester._rcs.bruno.keygenapp.base.MiniCaCertGen;

public class MiniCaServlet extends HttpServlet {
    private static final long serialVersionUID = -1103006284486954147L;
    private final transient Configuration configuration = new Configuration();

    @Override
    public void init() throws ServletException {
        super.init();

        /**
         * Initialises the servlet: loads the keystore/keys to use to sign the
         * assertions and the issuer name.
         */
        this.configuration.init(this);
    }

    @Override
    protected void doGet(HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException {
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    @Override
    protected void doPost(HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException {
        try {
            String webId = request.getParameter("webid");
            String spkacData = request.getParameter("spkac");
            String pemCsrData = request.getParameter("csrdata");
            String cn = request.getParameter("cn");

            Date startDate = new Date();
            Date endDate = new Date(startDate.getTime() + 365L * 24L * 60L
                    * 60L * 1000L);

            X509Name subjectDn;
            if ((cn == null) || cn.isEmpty()) {
                subjectDn = new X509Name(new DERSequence());
            } else {
                subjectDn = new X509Name("CN=" + cn);
            }

            X509Certificate cert;
            if ((spkacData == null) || spkacData.isEmpty()) {
                cert = MiniCaCertGen.createCertFromPemCsr(this.configuration
                        .getCaPublicKey(), this.configuration.getCaPrivKey(),
                        pemCsrData, subjectDn, this.configuration
                                .getIssuerName(), startDate, endDate, webId,
                        BigInteger.valueOf(this.configuration
                                .nextCertificateSerialNumber()));
                StringWriter sw = new StringWriter();
                PEMWriter pemWriter = new PEMWriter(sw);
                pemWriter.writeObject(cert);
                pemWriter.close();
                String pemCert = sw.toString();

                response.setContentType("application/x-x509-user-cert");
                response.setContentLength(pemCert.length());
                response.getWriter().print(pemCert);
            } else {
                cert = MiniCaCertGen.createCertFromSpkac(this.configuration
                        .getCaPublicKey(), this.configuration.getCaPrivKey(),
                        spkacData, subjectDn, this.configuration
                                .getIssuerName(), startDate, endDate, webId,
                        BigInteger.valueOf(this.configuration
                                .nextCertificateSerialNumber()));
                byte[] encodedCert = cert.getEncoded();
                response.setContentType("application/x-x509-user-cert");
                response.setContentLength(encodedCert.length);
                response.getOutputStream().write(encodedCert);
            }
        } catch (InvalidKeyException e) {
            throw new ServletException(e);
        } catch (IllegalStateException e) {
            throw new ServletException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new ServletException(e);
        } catch (SignatureException e) {
            throw new ServletException(e);
        } catch (CertificateException e) {
            throw new ServletException(e);
        } catch (NoSuchProviderException e) {
            throw new ServletException(e);
        }
    }
}
