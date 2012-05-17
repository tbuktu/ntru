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

package net.sf.ntru.polynomial;

public interface Polynomial {
    
    /**
     * Multiplies the polynomial by an <code>IntegerPolynomial</code>,
     * taking the indices mod <code>N</code>.
     * @param poly2 a polynomial
     * @return the product of the two polynomials
     */
    IntegerPolynomial mult(IntegerPolynomial poly2);
    
    /**
     * Multiplies the polynomial by an <code>IntegerPolynomial</code>,
     * taking the coefficient values mod <code>modulus</code> and the indices mod <code>N</code>.
     * @param poly2 a polynomial
     * @param modulus a modulus to apply
     * @return the product of the two polynomials
     */
    IntegerPolynomial mult(IntegerPolynomial poly2, int modulus);
    
    /**
     * Returns a polynomial that is equal to this polynomial (in the sense that {@link #mult(IntegerPolynomial, int)}
     * returns equal <code>IntegerPolynomial</code>s). The new polynomial is guaranteed to be independent of the original.
     * @return a new <code>IntegerPolynomial</code>.
     */
    IntegerPolynomial toIntegerPolynomial();
    
    /**
     * Multiplies the polynomial by a <code>BigIntPolynomial</code>, taking the indices mod N. Does not
     * change this polynomial but returns the result as a new polynomial.<br/>
     * Both polynomials must have the same number of coefficients.
     * @param poly2 the polynomial to multiply by
     * @return a new polynomial
     */
    BigIntPolynomial mult(BigIntPolynomial poly2);
}