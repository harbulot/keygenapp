/*
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
  Contributor...: Henry Story
 */

package net.bblfish.dev.foafssl.xwiki.internal;

import net.bblfish.dev.foafssl.keygen.Certificate;
import net.bblfish.dev.foafssl.keygen.KeygenService;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.logging.AbstractLogEnabled;
import org.xwiki.component.phase.Initializable;
import org.xwiki.component.phase.InitializationException;
import org.xwiki.script.service.ScriptService;

import java.security.InvalidParameterException;

/**
 * Component that can then be called by XWiki scripts, that can then call CertificateService.
 * <p/>
 * @author Bruno Harbulot
 * @author Henry Story
 * Date: Feb 17, 2010
 * Time: 3:46:22 PM
 */
@Component("foafssl")
public class CertificateScriptService extends AbstractLogEnabled implements ScriptService, KeygenService, Initializable {
    net.bblfish.dev.foafssl.keygen.impl.KeygenService servImp;


    public void initialize() throws InitializationException {
        servImp = new net.bblfish.dev.foafssl.keygen.impl.KeygenService();
        try {
            servImp.initialize();
        } catch (Exception e) {
            throw new InitializationException("initialisation error",e);
        }

    }

    public Certificate createFromPEM(String pemCsr) {
        return servImp.createFromPEM(pemCsr);
    }

    public Certificate createFromSpkac(String spkac) throws InvalidParameterException {
        return servImp.createFromSpkac(spkac);
    }


}
