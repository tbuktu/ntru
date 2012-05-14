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

import static net.sf.ntru.util.ArrayEncoder.toByteArray;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

import net.sf.ntru.encrypt.IndexGenerator;
import net.sf.ntru.encrypt.NtruEncrypt;
import net.sf.ntru.exception.NtruException;
import net.sf.ntru.util.ArrayEncoder;

/**
 * A <code>TernaryPolynomial</code> with a "low" number of nonzero coefficients.<br/>
 * Coefficients are represented as two arrays, one containing the indices of one-values
 * and the other containing indices of negative ones.
 */
public class SparseTernaryPolynomial implements TernaryPolynomial {
    /** Number of bits to use for each coefficient. Determines the upper bound for <code>N</code>. */
    private static final int BITS_PER_INDEX = 11;
    
    private int N;
    private int[] ones;
    private int[] negOnes;
    
    /**
     * Constructs a new polynomial.
     * @param N total number of coefficients including zeros
     * @param ones indices of coefficients equal to 1 <b>in ascending order</b>
     * @param negOnes indices of coefficients equal to -1 <b>in ascending order</b>
     */
    SparseTernaryPolynomial(int N, int[] ones, int[] negOnes) {
        this.N = N;
        this.ones = ones;
        this.negOnes = negOnes;
    }
    
    /**
     * Constructs a <code>DenseTernaryPolynomial</code> from a <code>IntegerPolynomial</code>. The two polynomials are
     * independent of each other.
     * @param intPoly the original polynomial
     */
    public SparseTernaryPolynomial(IntegerPolynomial intPoly) {
        this(intPoly.coeffs);
    }
    
    /**
     * Constructs a new <code>SparseTernaryPolynomial</code> with a given set of coefficients.
     * @param coeffs the coefficients
     * @throws NtruException if the coefficients are not ternary
     */
    public SparseTernaryPolynomial(int[] coeffs) {
        N = coeffs.length;
        ones = new int[N];
        negOnes = new int[N];
        int onesIdx = 0;
        int negOnesIdx = 0;
        for (int i=0; i<N; i++) {
            int c = coeffs[i];
            switch(c) {
            case 1:
                ones[onesIdx++] = i; break;
            case -1:
                negOnes[negOnesIdx++] = i; break;
            case 0:
                break;
            default:
                throw new NtruException("Illegal value: " + c + ", must be one of {-1, 0, 1}");
            }
        }
        ones = Arrays.copyOf(ones, onesIdx);
        negOnes = Arrays.copyOf(negOnes, negOnesIdx);
    }
    
    /**
     * Decodes a polynomial encoded with {@link #toBinary()}.
     * @param is an input stream containing an encoded polynomial
     * @param N number of coefficients in the polynomial
     * @return the decoded polynomial
     * @throws IOException 
     */
    static SparseTernaryPolynomial fromBinary(InputStream is, int N) throws IOException {
        int numOnes = readShort(is);   // number of coefficients equal to 1
        int numNegOnes = readShort(is);   // number of coefficients equal to -1
        
        int maxIndex = 1 << BITS_PER_INDEX;
        int bitsPerIndex = 32 - Integer.numberOfLeadingZeros(maxIndex-1);
        
        int data1Len = (numOnes*bitsPerIndex+7) / 8;
        byte[] data1 = ArrayEncoder.readFullLength(is, data1Len);
        int[] ones = ArrayEncoder.decodeModQ(data1, numOnes, maxIndex);
        
        int data2Len = (numNegOnes*bitsPerIndex+7) / 8;
        byte[] data2 = ArrayEncoder.readFullLength(is, data2Len);
        int[] negOnes = ArrayEncoder.decodeModQ(data2, numNegOnes, maxIndex);
        
        return new SparseTernaryPolynomial(N, ones, negOnes);
    }
    
    /**
     * Reads two bytes from an <code>InputStream</code> into an <code>int</code>.
     * @param is an input stream
     * @return a number containing two bytes from the input stream
     * @throws IOException
     */
    private static int readShort(InputStream is) throws IOException {
        return is.read()*256 + is.read();
    }
    
    /**
     * Generates a random polynomial with <code>numOnes</code> coefficients equal to 1,
     * <code>numNegOnes</code> coefficients equal to -1, and the rest equal to 0.
     * @param N number of coefficients
     * @param numOnes number of 1's
     * @param numNegOnes number of -1's
     * @param rng the random number generator to use
     */
    public static SparseTernaryPolynomial generateRandom(int N, int numOnes, int numNegOnes, Random rng) {
        int[] coeffs = new int[N];   // an IntegerPolynomial-style representation of the new polynomial
        
        int[] ones = new int[numOnes];
        int i = 0;
        while (i < numOnes) {
            int r = rng.nextInt(N);
            if (coeffs[r] == 0) {
                ones[i] = r;
                coeffs[r] = 1;
                i++;
            }
        }
        Arrays.sort(ones);
        
        int[] negOnes = new int[numNegOnes];
        i = 0;
        while (i < numNegOnes) {
            int r = rng.nextInt(N);
            if (coeffs[r] == 0) {
                negOnes[i] = r;
                coeffs[r] = -1;
                i++;
            }
        }
        Arrays.sort(negOnes);
        
        return new SparseTernaryPolynomial(N, ones, negOnes);
    }
    
    /**
     * Generates a blinding polynomial using an {@link IndexGenerator}.
     * @param ig an Index Generator
     * @param N the number of coefficients
     * @param dr the number of ones / negative ones
     * @return a blinding polynomial
     * @see NtruEncrypt#generateBlindingPoly(byte[])
     */
    public static SparseTernaryPolynomial generateBlindingPoly(IndexGenerator ig, int N, int dr) {
        int[] coeffs = new int[N];   // an IntegerPolynomial-style representation of the new polynomial
        
        int[] ones = new int[dr];
        int i = 0;
        while (i < dr) {
            int r = ig.nextIndex();
            if (coeffs[r] == 0) {
                ones[i] = r;
                coeffs[r] = 1;
                i++;
            }
        }
        
        int[] negOnes = new int[dr];
        i = 0;
        while (i < dr) {
            int r = ig.nextIndex();
            if (coeffs[r] == 0) {
                negOnes[i] = r;
                coeffs[r] = -1;
                i++;
            }
        }
        
        return new SparseTernaryPolynomial(N, ones, negOnes);
    }
    
    @Override
    public IntegerPolynomial mult(IntegerPolynomial poly2) {
        int[] b = poly2.coeffs;
        if (b.length != N)
            throw new NtruException("Number of coefficients must be the same");
        
        int[] c = new int[N];
        for (int i: ones) {
            int j = N - 1 - i;
            for(int k=N-1; k>=0; k--) {
                c[k] += b[j];
                j--;
                if (j < 0)
                    j = N - 1;
            }
        }
        
        for (int i: negOnes) {
            int j = N - 1 - i;
            for(int k=N-1; k>=0; k--) {
                c[k] -= b[j];
                j--;
                if (j < 0)
                    j = N - 1;
            }
        }
        
        return new IntegerPolynomial(c);
    }
    
    @Override
    public IntegerPolynomial mult(IntegerPolynomial poly2, int modulus) {
        IntegerPolynomial c = mult(poly2);
        c.mod(modulus);
        return c;
    }

    public BigIntPolynomial mult(BigIntPolynomial poly2) {
        BigInteger[] b = poly2.coeffs;
        if (b.length != N)
            throw new NtruException("Number of coefficients must be the same");
        
        BigInteger[] c = new BigInteger[N];
        for (int i=0; i<N; i++)
            c[i] = BigInteger.ZERO;
        
        for (int i: ones) {
            int j = N - 1 - i;
            for(int k=N-1; k>=0; k--) {
                c[k] = c[k].add(b[j]);
                j--;
                if (j < 0)
                    j = N - 1;
            }
        }
        
        for (int i: negOnes) {
            int j = N - 1 - i;
            for(int k=N-1; k>=0; k--) {
                c[k] = c[k].subtract(b[j]);
                j--;
                if (j < 0)
                    j = N - 1;
            }
        }
        
        return new BigIntPolynomial(c);
    }
    
    @Override
    public int[] getOnes() {
        return ones;
    }
    
    @Override
    public int[] getNegOnes() {
        return negOnes;
    }

    /**
     * Encodes the polynomial to a byte array writing <code>BITS_PER_INDEX</code> bits for each coefficient.
     * @return the encoded polynomial
     */
    byte[] toBinary() {
        int maxIndex = 1 << BITS_PER_INDEX;
        byte[] bin1 = ArrayEncoder.encodeModQ(ones, maxIndex);
        byte[] bin2 = ArrayEncoder.encodeModQ(negOnes, maxIndex);
        
        byte[] bin = ArrayEncoder.concatenate(toByteArray(ones.length), toByteArray(negOnes.length), bin1, bin2);
        return bin;
    }
    
    @Override
    public IntegerPolynomial toIntegerPolynomial() {
        int[] coeffs = new int[N];
        for (int i: ones)
            coeffs[i] = 1;
        for (int i: negOnes)
            coeffs[i] = -1;
        return new IntegerPolynomial(coeffs);
    }
    
    @Override
    public int size() {
        return N;
    }
    
    @Override
    public void clear() {
        for (int i=0; i<ones.length; i++)
            ones[i] = 0;
        for (int i=0; i<negOnes.length; i++)
            negOnes[i] = 0;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + N;
        result = prime * result + Arrays.hashCode(negOnes);
        result = prime * result + Arrays.hashCode(ones);
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        SparseTernaryPolynomial other = (SparseTernaryPolynomial) obj;
        if (N != other.N)
            return false;
        if (!Arrays.equals(negOnes, other.negOnes))
            return false;
        if (!Arrays.equals(ones, other.ones))
            return false;
        return true;
    }
}