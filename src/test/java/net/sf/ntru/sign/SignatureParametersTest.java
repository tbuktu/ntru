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

package net.sf.ntru.sign;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import net.sf.ntru.sign.SignatureParameters;

import org.junit.Test;

public class SignatureParametersTest {
    
    @Test
    public void testLoadSave() throws IOException {
        SignatureParameters params = SignatureParameters.TEST157;
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        params.writeTo(os);
        ByteArrayInputStream is = new ByteArrayInputStream(os.toByteArray());
        assertEquals(params, new SignatureParameters(is));
    }

    @Test
    public void testEqualsHashCode() throws IOException {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        SignatureParameters.TEST157.writeTo(os);
        ByteArrayInputStream is = new ByteArrayInputStream(os.toByteArray());
        SignatureParameters params = new SignatureParameters(is);
        
        assertEquals(params, SignatureParameters.TEST157);
        assertEquals(params.hashCode(), SignatureParameters.TEST157.hashCode());
        
        params.N += 1;
        assertFalse(params.equals(SignatureParameters.TEST157));
        assertFalse(SignatureParameters.TEST157.equals(params));
        assertFalse(params.hashCode() == SignatureParameters.TEST157.hashCode());
    }
    
    @Test
    public void testClone() {
        SignatureParameters params = SignatureParameters.TEST157;
        assertEquals(params, params.clone());
    }
}