/**
 * This software is dual-licensed. You may choose either the
 * Non-Profit Open Software License version 3.0, or any license
 * agreement into which you enter with Security Innovation, Inc.
 * 
 * Use of this code, or certain portions thereof, implements
 * inventions covered by claims of one or more of the following
 * U.S. Patents and/or foreign counterpart patents, owned by
 * Security Innovation, Inc.:
 * 7,308,097, 7,031,468, 6,959,085, 6,298,137, and 6,081,597.
 * Practice or sale of the inventions embodied in the code hereof
 * requires a license from Security Innovation Inc. at:
 * 
 * 187 Ballardvale St, Suite A195
 * Wilmington, MA 01887
 * USA
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