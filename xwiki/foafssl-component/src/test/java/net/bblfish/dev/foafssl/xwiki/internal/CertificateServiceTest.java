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

package net.bblfish.dev.foafssl.xwiki.internal;

import junit.framework.TestCase;
import net.bblfish.dev.foafssl.xwiki.*;
import net.bblfish.dev.foafssl.xwiki.internal.CertificateScriptService;
import org.bouncycastle.asn1.x509.X509Name;
import org.xwiki.component.phase.InitializationException;


/**
 * Tests for the {@link net.bblfish.dev.foafssl.xwiki.CertificateService} component.
 *
 * @version $Id: $
 */
public class CertificateServiceTest extends TestCase {
    static String spkac = "MIIBRzCBsTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAwWxHp09gHwgec98X\n" +
            "2hxynxlAlN9IeiSu7T1CSry4uMPCkujkcpTg0n7ofhHvke/kwlv9QpK/Ko4gcQTI\n" +
            "nWu3Sl5hcRdP1KvRTq+VdyPp0QUTStlri3uYMZcOC5yXFqAFVywRWvQDtBYMYtqp\n" +
            "KcyvaRpKKRC+lpWTIjbvOSgfy4UCAwEAARYNVGhlQ2hhbGxlbmdlMTANBgkqhkiG\n" +
            "9w0BAQQFAAOBgQClhG6itMJneOfwSt5gaCzg/HRt94WKtJivbLvlYwNi2NkZu014\n" +
            "308EhhG0onhBIy5hXopa7pvYzqMv2gbipj89ucqoUYybqaoP+qJ0eDbSlJOaISlB\n" +
            "2b6nVDYhlj/ihT40qv6+3WNdiUgayB+INLQW1hPvqPirjHfMJOfpfQcwIw==";

    /**
     * test the creation of an spkac certificate
     *
     * @throws Exception
     */
    public void testSpkac() throws Exception {
        CertificateScriptService srvc = new CertificateScriptService();
        srvc.initialize();
        Certificate cert = srvc.createFromSpkac(spkac);
        PubKey spk = cert.getSubjectPublicKey();
        assertNotNull(spk);
        assertTrue(spk instanceof RSAPubKey);
        assertEquals("the expected and real values don't match",
                "c16c47a74f601f081e73df17da1c729f194094df487a24aeed3d424abcb8\r\n" +
                "b8c3c292e8e47294e0d27ee87e11ef91efe4c25bfd4292bf2a8e207104c8\r\n" +
                "9d6bb74a5e6171174fd4abd14eaf957723e9d105134ad96b8b7b9831970e\r\n" +
                "0b9c9716a005572c115af403b4160c62daa929ccaf691a4a2910be969593\r\n" +
                "2236ef39281fcb85\r\n",((RSAPubKey) spk).getHexModulus());
        assertEquals("int exponent is not correct","65537",((RSAPubKey) spk).getIntExponent());
        cert.addDurationInDays("3");
        cert.setSubjectCommonName("Test");
        cert.setSubjectWebID("http://test.com/#me");
        CertSerialisation certByte = cert.getSerialisation();
        //test that the returned certificate contains the correct values...
    }

    public void testDN() throws Exception {
        new X509Name(CertificateService.issuer);
    }

    public void testInit() throws InitializationException {
        CertificateScriptService srvc = new CertificateScriptService();
        srvc.initialize();
    }
 
}
