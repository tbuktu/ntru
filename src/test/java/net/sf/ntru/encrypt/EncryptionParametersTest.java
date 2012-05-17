/**
 * Copyright (c) 2011, Tim Buktu
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package net.sf.ntru.encrypt;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.junit.Test;

public class EncryptionParametersTest {
    
    @Test
    public void testLoadSave() throws IOException {
        EncryptionParameters params = EncryptionParameters.EES1499EP1;
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        params.writeTo(os);
        ByteArrayInputStream is = new ByteArrayInputStream(os.toByteArray());
        assertEquals(params, new EncryptionParameters(is));
    }

    @Test
    public void testEqualsHashCode() throws IOException {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        EncryptionParameters.EES1499EP1.writeTo(os);
        ByteArrayInputStream is = new ByteArrayInputStream(os.toByteArray());
        EncryptionParameters params = new EncryptionParameters(is);
        
        assertEquals(params, EncryptionParameters.EES1499EP1);
        assertEquals(params.hashCode(), EncryptionParameters.EES1499EP1.hashCode());
        
        params.N += 1;
        assertFalse(params.equals(EncryptionParameters.EES1499EP1));
        assertFalse(EncryptionParameters.EES1499EP1.equals(params));
        assertFalse(params.hashCode() == EncryptionParameters.EES1499EP1.hashCode());
    }
    
    @Test
    public void testClone() {
        EncryptionParameters params = EncryptionParameters.APR2011_439;
        assertEquals(params, params.clone());
        
        params = EncryptionParameters.APR2011_439_FAST;
        assertEquals(params, params.clone());
    }
}