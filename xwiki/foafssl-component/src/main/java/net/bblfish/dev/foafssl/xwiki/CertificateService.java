/*
 * New BSD license: http://opensource.org/licenses/bsd-license.php
 *
 *  Copyright (c) 2010.
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
 *  - Neither the name of Sun Microsystems, Inc. nor the names of its contributors
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

package net.bblfish.dev.foafssl.xwiki;

import org.xwiki.component.annotation.ComponentRole;

import java.security.InvalidParameterException;

/**
 * A service to get Certificates from <a href="http://en.wikipedia.org/wiki/Certification_request">Certification Requests</a>
 * These can the be used to get information about the CSR's public key, and generate a certifiate to return to the server.
 *
 * User: hjs
 * Date: Feb 14, 2010
 * Time: 5:45:42 PM
 * To change this template use File | Settings | File Templates.
 */
@ComponentRole
public interface CertificateService {
    static final String issuer = "O=FOAF\\+SSL, OU=The Community of Self Signers, CN=Not a Certification Authority"; //the exact name for the FOAF+SSL issuer is still being decided
                                          
    /**
     * Creates a certificate stub from the given <a href="http://en.wikipedia.org/wiki/PEM">PEM</a> <a href="http://en.wikipedia.org/wiki/Certification_request">CSR</a>.
     * The returned certificate will be filled out with info from the CSR and a number of other defaults.
     * Other information may then be added programatically before generating a certificate to return.
     *
     * Internet Explorer sends PEM CSRs to the server.
     *
     * @param csr a <a href="http://en.wikipedia.org/wiki/PEM">PEM</a> <a href="http://en.wikipedia.org/wiki/Certification_request">Certificate Signing Request</a>
     * @return a certificate using the CSR, and cert defaults
     * @throws java.security.InvalidParameterException  in case the parameter is null
     */
    Certificate createFromPEM(String csr) throws InvalidParameterException;

    /**
     * Creates a certificate stub from the given <a href="http://en.wikipedia.org/wiki/Spkac">SPKAC</a> <a href="http://en.wikipedia.org/wiki/Certification_request">CSR</a>.
     * The returned certificate will be filled out with info from the CSR and a number of other defaults.
     * Other information may then be added programatically before generating a certificate to return.
     *
     * Safari, Firefox, Opera, return through the <keygen> element an SPKAC request
     * (see the specification in html5)
     *
     * @param spkac a <a href="http://en.wikipedia.org/wiki/Spkac">SPKAC</a> <a href="http://en.wikipedia.org/wiki/Certification_request">Certificate Signing Request</a>
     * @return a certificate using the CSR, and cert defaults
     * @throws java.security.InvalidParameterException  thrown if parameter is null
     */
    Certificate createFromSpkac(String spkac) throws InvalidParameterException;

     

}
