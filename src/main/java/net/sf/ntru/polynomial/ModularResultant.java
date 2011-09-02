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

package net.sf.ntru.polynomial;

import java.math.BigInteger;

import net.sf.ntru.euclid.BigIntEuclidean;

/** A resultant modulo a <code>BigInteger</code> */
public class ModularResultant extends Resultant {
    BigInteger modulus;
    
    ModularResultant(BigIntPolynomial rho, BigInteger res, BigInteger modulus) {
        super(rho, res);
        this.modulus = modulus;
    }
    
    /**
     * Calculates a <code>rho</code> modulo <code>m1*m2</code> from
     * two resultants whose <code>rho</code>s are modulo <code>m1</code> and <code>m2</code>.<br/>
     * </code>res</code> is set to <code>null</code>.
     * @param modRes1
     * @param modRes2
     * @return <code>rho</code> modulo <code>modRes1.modulus * modRes2.modulus</code>, and <code>null</code> for </code>res</code>.
     */
    static ModularResultant combineRho(ModularResultant modRes1, ModularResultant modRes2) {
        BigInteger mod1 = modRes1.modulus;
        BigInteger mod2 = modRes2.modulus;
        BigInteger prod = mod1.multiply(mod2);
        BigIntEuclidean er = BigIntEuclidean.calculate(mod2, mod1);
        
        BigIntPolynomial rho1 = modRes1.rho.clone();
        rho1.mult(er.x.multiply(mod2));
        BigIntPolynomial rho2 = modRes2.rho.clone();
        rho2.mult(er.y.multiply(mod1));
        rho1.add(rho2);
        rho1.mod(prod);

        return new ModularResultant(rho1, null, prod);
    }
}