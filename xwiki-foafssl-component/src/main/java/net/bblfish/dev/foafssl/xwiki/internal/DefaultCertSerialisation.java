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

import net.bblfish.dev.foafssl.xwiki.CertSerialisation;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.Charset;

/**
 * Implementation of CertSerialisation
 * 
 * User: hjs
 * Date: Feb 18, 2010
 * Time: 7:27:05 PM
 * To change this template use File | Settings | File Templates.
 */
public class DefaultCertSerialisation implements CertSerialisation {
    byte[] sz;
    String mime = "application/x-x509-user-cert";

    DefaultCertSerialisation(byte[] serialisation) {
        sz = serialisation;
    }

    public int getLength() {
        return sz.length;
    }

    public String getMimeType() {
        return mime;
    }

    public void write(OutputStream out) throws IOException {
        out.write(sz);
    }

    /**
     * Should not be used, only for testing!
     * @return a string representation of the output
     */
    public String toString() {
        return "DO NOT USE FOR OUTPUT! use write(OutputStream out) instead!\r\n"+
                new String(sz, Charset.forName("UTF-8"));

    }
}