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

package net.sf.ntru;

import static java.math.BigInteger.ONE;
import static java.math.BigInteger.ZERO;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

/**
 * A polynomial with <code>int</code> coefficients.<br/>
 * Some methods (like <code>add</code>) change the polynomial, others (like <code>mult</code>) do
 * not but return the result as a new polynomial.
 */
class IntegerPolynomial {
    /**
     * Bit string to coefficient conversion table from P1363.1. Also found at
     * {@link http://stackoverflow.com/questions/1562548/how-to-make-a-message-into-a-polynomial}
     * <p/>
     * Convert each three-bit quantity to two ternary coefficients as follows, and concatenate the resulting
     * ternary quantities to obtain [the output].
     * <p/>
     * <code>
     * {0, 0, 0} -> {0, 0}<br/>
     * {0, 0, 1} -> {0, 1}<br/>
     * {0, 1, 0} -> {0, -1}<br/>
     * {0, 1, 1} -> {1, 0}<br/>
     * {1, 0, 0} -> {1, 1}<br/>
     * {1, 0, 1} -> {1, -1}<br/>
     * {1, 1, 0} -> {-1, 0}<br/>
     * {1, 1, 1} -> {-1, 1}<br/>
     * </code>
     */
    static final int[] COEFF1_TABLE = {0, 0, 0, 1, 1, 1, -1, -1};
    static final int[] COEFF2_TABLE = {0, 1, -1, 0, 1, -1, 0, 1};
    /**
     * Coefficient to bit string conversion table from P1363.1. Also found at
     * {@link http://stackoverflow.com/questions/1562548/how-to-make-a-message-into-a-polynomial}
     * <p/>
     * Convert each set of two ternary coefficients to three bits as follows, and concatenate the resulting bit
     * quantities to obtain [the output]:
     * <p/>
     * <code>
     * {-1, -1} -> set "fail" to 1 and set bit string to {1, 1, 1}
     * {-1, 0} -> {1, 1, 0}<br/>
     * {-1, 1} -> {1, 1, 1}<br/>
     * {0, -1} -> {0, 1, 0}<br/>
     * {0, 0} -> {0, 0, 0}<br/>
     * {0, 1} -> {0, 0, 1}<br/>
     * {1, -1} -> {1, 0, 1}<br/>
     * {1, 0} -> {0, 1, 1}<br/>
     * {1, 1} -> {1, 0, 0}<br/>
     * </code>
     */
    static final int[] BIT1_TABLE = {1, 1, 1, 0, 0, 0, 1, 0, 1};
    static final int[] BIT2_TABLE = {1, 1, 1, 1, 0, 0, 0, 1, 0};
    static final int[] BIT3_TABLE = {1, 0, 1, 0, 0, 1, 1, 1, 0};
    /** prime numbers &gt; <code>10^4</code> */
    private static final int[] PRIMES = new int[] {
        10007, 10009, 10037, 10039, 10061, 10067, 10069, 10079, 10091, 10093, 
        10099, 10103, 10111, 10133, 10139, 10141, 10151, 10159, 10163, 10169, 
        10177, 10181, 10193, 10211, 10223, 10243, 10247, 10253, 10259, 10267, 
        10271, 10273, 10289, 10301, 10303, 10313, 10321, 10331, 10333, 10337, 
        10343, 10357, 10369, 10391, 10399, 10427, 10429, 10433, 10453, 10457, 
        10459, 10463, 10477, 10487, 10499, 10501, 10513, 10529, 10531, 10559, 
        10567, 10589, 10597, 10601, 10607, 10613, 10627, 10631, 10639, 10651, 
        10657, 10663, 10667, 10687, 10691, 10709, 10711, 10723, 10729, 10733, 
        10739, 10753, 10771, 10781, 10789, 10799, 10831, 10837, 10847, 10853, 
        10859, 10861, 10867, 10883, 10889, 10891, 10903, 10909, 10937, 10939, 
        10949, 10957, 10973, 10979, 10987, 10993, 11003, 11027, 11047, 11057, 
        11059, 11069, 11071, 11083, 11087, 11093, 11113, 11117, 11119, 11131, 
        11149, 11159, 11161, 11171, 11173, 11177, 11197, 11213, 11239, 11243, 
        11251, 11257, 11261, 11273, 11279, 11287, 11299, 11311, 11317, 11321, 
        11329, 11351, 11353, 11369, 11383, 11393, 11399, 11411, 11423, 11437, 
        11443, 11447, 11467, 11471, 11483, 11489, 11491, 11497, 11503, 11519, 
        11527, 11549, 11551, 11579, 11587, 11593, 11597, 11617, 11621, 11633, 
        11657, 11677, 11681, 11689, 11699, 11701, 11717, 11719, 11731, 11743, 
        11777, 11779, 11783, 11789, 11801, 11807, 11813, 11821, 11827, 11831, 
        11833, 11839, 11863, 11867, 11887, 11897, 11903, 11909, 11923, 11927, 
        11933, 11939, 11941, 11953, 11959, 11969, 11971, 11981, 11987, 12007, 
        12011, 12037, 12041, 12043, 12049, 12071, 12073, 12097, 12101, 12107, 
        12109, 12113, 12119, 12143, 12149, 12157, 12161, 12163, 12197, 12203, 
        12211, 12227, 12239, 12241, 12251, 12253, 12263, 12269, 12277, 12281, 
        12289, 12301, 12323, 12329, 12343, 12347, 12373, 12377, 12379, 12391, 
        12401, 12409, 12413, 12421, 12433, 12437, 12451, 12457, 12473, 12479, 
        12487, 12491, 12497, 12503, 12511, 12517, 12527, 12539, 12541, 12547, 
        12553, 12569, 12577, 12583, 12589};
    private static final List<BigInteger> BIGINT_PRIMES;

    static {
        BIGINT_PRIMES = new ArrayList<BigInteger>();
        for (int p: PRIMES)
            BIGINT_PRIMES.add(BigInteger.valueOf(p));
    }
    
    int[] coeffs;
    
    /**
     * Constructs a new polynomial with <code>N</code> coefficients initialized to 0.
     * @param N the number of coefficients
     */
    IntegerPolynomial(int N) {
        coeffs = new int[N];
    }
    
    /**
     * Constructs a new polynomial with a given set of coefficients.
     * @param coeffs the coefficients
     */
    IntegerPolynomial(int[] coeffs) {
        this.coeffs = coeffs;
    }
    
    /**
     * Constructs a <code>IntegerPolynomial</code> from a <code>BigIntPolynomial</code>. The two polynomials are independent of each other.
     * @param p the original polynomial
     */
    IntegerPolynomial(BigIntPolynomial p) {
        coeffs = new int[p.coeffs.length];
        for (int i=0; i<p.coeffs.length; i++)
            coeffs[i] = p.coeffs[i].intValue();
    }
    
    /**
     * Decodes a byte array to a polynomial with <code>N</code> coefficients between -1 and 1.<br/>
     * Ignores any excess bytes.
     * @param data an encoded ternary polynomial
     * @param N number of coefficients
     * @return the decoded polynomial
     */
    static IntegerPolynomial fromBinary3(byte[] data, int N) {
        IntegerPolynomial poly = new IntegerPolynomial(N);
        int coeffIndex = 0;
        for (int bitIndex=0; bitIndex<data.length*8; ) {
            int bit1 = getBit(data, bitIndex++);
            int bit2 = getBit(data, bitIndex++);
            int bit3 = getBit(data, bitIndex++);
            int coeffTableIndex = bit1*4 + bit2*2 + bit3;
            poly.coeffs[coeffIndex++] = COEFF1_TABLE[coeffTableIndex];
            poly.coeffs[coeffIndex++] = COEFF2_TABLE[coeffTableIndex];
            // ignore bytes that can't fit
            if (coeffIndex > N-2)
                break;
        }
        return poly;
    }
    
    /**
     * Returns a polynomial with N coefficients between <code>0</code> and <code>q-1</code>.<br/>
     * <code>q</code> must be a power of 2.<br/>
     * Ignores any excess bytes.
     * @param data an encoded ternary polynomial
     * @param N number of coefficients
     * @param q
     * @return the decoded polynomial
     */
    static IntegerPolynomial fromBinary(byte[] data, int N, int q) {
        IntegerPolynomial poly = new IntegerPolynomial(N);
        int bitsPerCoeff = 31 - Integer.numberOfLeadingZeros(q);
        int numBits = N * bitsPerCoeff;
        int coeffIndex = 0;
        for (int bitIndex=0; bitIndex<numBits; bitIndex++) {
            if (bitIndex>0 && bitIndex%bitsPerCoeff==0)
                coeffIndex++;
            int bit = getBit(data, bitIndex);
            poly.coeffs[coeffIndex] += bit << (bitIndex%bitsPerCoeff);
        }
        return poly;
    }
    
    /**
     * Returns a polynomial with N coefficients between <code>0</code> and <code>q-1</code>.<br/>
     * <code>q</code> must be a power of 2.<br/>
     * Ignores any excess bytes.
     * @param buf an encoded ternary polynomial
     * @param N number of coefficients
     * @param q
     * @return the decoded polynomial
     */
    static IntegerPolynomial fromBinary(ByteBuffer buf, int N, int q) {
        int qBits = 31 - Integer.numberOfLeadingZeros(q);
        int size = (N*qBits+7) / 8;
        byte[] arr = new byte[size];
        buf.get(arr);
        return fromBinary(arr, N, q);
    }
    
    /**
     * Returns a polynomial with N coefficients between <code>0</code> and <code>q-1</code>.<br/>
     * <code>q</code> must be a power of 2.<br/>
     * Ignores any excess bytes.
     * @param is an encoded ternary polynomial
     * @param N number of coefficients
     * @param q
     * @return the decoded polynomial
     */
    static IntegerPolynomial fromBinary(InputStream is, int N, int q) throws IOException {
        int qBits = 31 - Integer.numberOfLeadingZeros(q);
        int size = (N*qBits+7) / 8;
        byte[] arr = new byte[size];
        is.read(arr);
        return fromBinary(arr, N, q);
    }
    
    private static int getBit(byte[] arr, int bitIndex) {
        int byteIndex = bitIndex / 8;
        int arrElem = arr[byteIndex] & 0xFF;
        return (arrElem >> (bitIndex%8)) & 1;
    }
    
    /**
     * Encodes a polynomial whose coefficients are between -1 and 1, to binary.
     * <code>coeffs[2*i]</code> and <code>coeffs[2*i+1]</code> must not both equal -1 for any integer </code>i<code>,
     * so this method is only safe to use with polynomials produced by <code>fromBinary3()</code>.
     * @return the encoded polynomial
     */
    byte[] toBinary3() {
        int numBits = (coeffs.length*3+2) / 2;
        int numBytes = (numBits+7) / 8;
        byte[] data = new byte[numBytes];
        int bitIndex = 0;
        int byteIndex = 0;
        for (int i=0; i<coeffs.length/2*2; ) {   // coeffs.length is an odd number, throw away the highest coeff
            int coeff1 = coeffs[i++] + 1;
            int coeff2 = coeffs[i++] + 1;
            if (coeff1==0 && coeff2==0)
                throw new NtruException("Illegal encoding!");
            int bitTableIndex = coeff1*3 + coeff2;
            int[] bits = new int[] {BIT1_TABLE[bitTableIndex], BIT2_TABLE[bitTableIndex], BIT3_TABLE[bitTableIndex]};
            for (int j=0; j<3; j++) {
                data[byteIndex] |= bits[j] << bitIndex;
                if (bitIndex == 7) {
                    bitIndex = 0;
                    byteIndex++;
                }
                else
                    bitIndex++;
            }
        }
        return data;
    }
    
    /**
     * Converts a polynomial whose coefficients are between -1 and 1, to binary.
     * @return the encoded polynomial
     */
    byte[] toBinary3Arith() {
        BigInteger sum = ZERO;
        for (int i=coeffs.length-1; i>=0; i--) {
            sum = sum.multiply(BigInteger.valueOf(3));
            sum = sum.add(BigInteger.valueOf(coeffs[i]+1));
        }
        
        int size = (BigInteger.valueOf(3).pow(coeffs.length).bitLength()+7) / 8;
        byte[] arr = sum.toByteArray();
        
        if (arr.length < size) {
            // pad with leading zeros so arr.length==size
            byte[] arr2 = new byte[size];
            System.arraycopy(arr, 0, arr2, size-arr.length, arr.length);
            return arr2;
        }
        
        if (arr.length > size)
            // drop sign bit
            arr = Arrays.copyOfRange(arr, 1, arr.length);
        return arr;
    }
    
    /**
     * Converts a byte array produced by toBinary3Arith() to a polynomial.
     * @param b a byte array
     * @param N number of coefficients
     * @return the decoded polynomial
     */
    static IntegerPolynomial fromBinary3Arith(byte[] b, int N) {
        BigInteger sum = new BigInteger(1, b);
        IntegerPolynomial p = new IntegerPolynomial(N);
        for (int i=0; i<N; i++) {
            p.coeffs[i] = sum.mod(BigInteger.valueOf(3)).intValue() - 1;
            if (p.coeffs[i] > 1)
                p.coeffs[i] -= 3;
            sum = sum.divide(BigInteger.valueOf(3));
        }
        return p;
    }
    
    /**
     * Reads data produced by toBinary3Arith() from a byte buffer and converts it to a polynomial.
     * @param b a byte buffer
     * @param N number of coefficients
     * @return the decoded polynomial
     */
    static IntegerPolynomial fromBinary3Arith(ByteBuffer buf, int N) {
        int size = (int)Math.ceil(N * Math.log(3) / Math.log(2) / 8);
        byte[] arr = new byte[size];
        buf.get(arr);
        return fromBinary3Arith(arr, N);
    }
    
    /**
     * Reads data produced by toBinary3Arith() from an input stream and converts it to a polynomial.
     * @param b an input stream
     * @param N number of coefficients
     * @return the decoded polynomial
     */
    static IntegerPolynomial fromBinary3Arith(InputStream is, int N) throws IOException {
        int size = (int)Math.ceil(N * Math.log(3) / Math.log(2) / 8);
        byte[] arr = new byte[size];
        is.read(arr);
        return fromBinary3Arith(arr, N);
    }
    
    /**
     * Encodes a polynomial whose coefficients are between 0 and q, to binary. q must be a power of 2.
     * @param q
     * @return the encoded polynomial
     */
    byte[] toBinary(int q) {
        int bitsPerCoeff = 31 - Integer.numberOfLeadingZeros(q);
        int numBits = coeffs.length * bitsPerCoeff;
        int numBytes = (numBits+7) / 8;
        byte[] data = new byte[numBytes];
        int bitIndex = 0;
        int byteIndex = 0;
        for (int i=0; i<coeffs.length; i++) {
            for (int j=0; j<bitsPerCoeff; j++) {
                int currentBit = (coeffs[i] >> j) & 1;
                data[byteIndex] |= currentBit << bitIndex;
                if (bitIndex == 7) {
                    bitIndex = 0;
                    byteIndex++;
                }
                else
                    bitIndex++;
            }
        }
        return data;
    }
    
    /** Multiplies the polynomial with another, taking the values mod modulus and the indices mod N */
    public IntegerPolynomial mult(IntegerPolynomial poly2, int modulus) {
        IntegerPolynomial c = mult(poly2);
        c.mod(modulus);
        return c;
    }
    
    /** Multiplies the polynomial with another, taking the indices mod N */
    public IntegerPolynomial mult(IntegerPolynomial poly2) {
        int N = coeffs.length;
        if (poly2.coeffs.length != N)
            throw new NtruException("Number of coefficients must be the same");
        
        IntegerPolynomial c = multRecursive(poly2);
        
        if (c.coeffs.length > N) {
            for (int k=N; k<c.coeffs.length; k++)
                c.coeffs[k-N] += c.coeffs[k];
            c.coeffs = Arrays.copyOf(c.coeffs, N);
        }
        return c;
    }
    
    /** Karazuba multiplication */
    private IntegerPolynomial multRecursive(IntegerPolynomial poly2) {
        int[] a = coeffs;
        int[] b = poly2.coeffs;
        
        int n = poly2.coeffs.length;
        if (n <= 32) {
            int cn = 2 * n - 1;
            IntegerPolynomial c = new IntegerPolynomial(new int[cn]);
            for (int k=0; k<cn; k++)
                for (int i=Math.max(0, k-n+1); i<=Math.min(k,n-1); i++)
                    c.coeffs[k] += b[i] * a[k-i];
            return c;
        }
        else {
            int n1 = n / 2;
            
            IntegerPolynomial a1 = new IntegerPolynomial(Arrays.copyOf(a, n1));
            IntegerPolynomial a2 = new IntegerPolynomial(Arrays.copyOfRange(a, n1, n));
            IntegerPolynomial b1 = new IntegerPolynomial(Arrays.copyOf(b, n1));
            IntegerPolynomial b2 = new IntegerPolynomial(Arrays.copyOfRange(b, n1, n));
            
            IntegerPolynomial A = a1.clone();
            A.add(a2);
            IntegerPolynomial B = b1.clone();
            B.add(b2);
            
            IntegerPolynomial c1 = a1.multRecursive(b1);
            IntegerPolynomial c2 = a2.multRecursive(b2);
            IntegerPolynomial c3 = A.multRecursive(B);
            c3.sub(c1);
            c3.sub(c2);
            
            IntegerPolynomial c = new IntegerPolynomial(2*n-1);
            for (int i=0; i<c1.coeffs.length; i++)
                c.coeffs[i] = c1.coeffs[i];
            for (int i=0; i<c3.coeffs.length; i++)
                c.coeffs[n1+i] += c3.coeffs[i];
            for (int i=0; i<c2.coeffs.length; i++)
                c.coeffs[2*n1+i] += c2.coeffs[i];
            return c;
        }
    }
    
    /**
     * Computes the inverse mod <code>q; q</code> must be a power of 2.<br/>
     * Returns <code>null</code> if the polynomial is not invertible.
     * @param q the modulus
     * @return a new polynomial
     */
    IntegerPolynomial invertFq(int q) {
        int N = coeffs.length;
        int k = 0;
        IntegerPolynomial b = new IntegerPolynomial(N+1);
        b.coeffs[0] = 1;
        IntegerPolynomial c = new IntegerPolynomial(N+1);
        IntegerPolynomial f = new IntegerPolynomial(N+1);
        f.coeffs = Arrays.copyOf(coeffs, N+1);
        // set g(x) = x^N − 1
        IntegerPolynomial g = new IntegerPolynomial(N+1);
        g.coeffs[0] = -1;
        g.coeffs[N] = 1;
        while (true) {
            while (f.coeffs[0] == 0) {
                for (int i=1; i<=N; i++) {
                    f.coeffs[i-1] = f.coeffs[i];   // f(x) = f(x) / x
                    c.coeffs[N+1-i] = c.coeffs[N-i];   // c(x) = c(x) * x
                }
                f.coeffs[N] = 0;
                c.coeffs[0] = 0;
                k++;
                if (f.equalsZero())
                    return null;   // not invertible
            }
            if (f.equalsOne())
                break;
            if (f.degree() < g.degree()) {
                // exchange f and g
                IntegerPolynomial temp = f;
                f = g;
                g = temp;
                // exchange b and c
                temp = b;
                b = c;
                c = temp;
            }
            f.add(g, 2);
            b.add(c, 2);
        }
        
        if (b.coeffs[N] != 0)
            return null;
        // Fq(x) = x^(N-k) * b(x)
        IntegerPolynomial Fq = new IntegerPolynomial(N);
        int j = 0;
        k %= N;
        for (int i=N-1; i>=0; i--) {
            j = i - k;
            if (j < 0)
                j += N;
            Fq.coeffs[j] = b.coeffs[i];
        }
        
        // inverse mod 2 --> inverse mod q
        int v = 2;
        while (v < q) {
            v *= 2;
            IntegerPolynomial temp = new IntegerPolynomial(Arrays.copyOf(Fq.coeffs, Fq.coeffs.length));
            temp.mult2(v);
            Fq = mult(Fq, v).mult(Fq, v);
            temp.sub(Fq, v);
            Fq = temp;
        }
        
        Fq.ensurePositive(q);
        return Fq;
    }
    
    /**
     * Computes the inverse mod 3.
     * Returns <code>null</code> if the polynomial is not invertible.
     * @return a new polynomial
     */
    IntegerPolynomial invertF3() {
        int N = coeffs.length;
        int k = 0;
        IntegerPolynomial b = new IntegerPolynomial(N+1);
        b.coeffs[0] = 1;
        IntegerPolynomial c = new IntegerPolynomial(N+1);
        IntegerPolynomial f = new IntegerPolynomial(N+1);
        f.coeffs = Arrays.copyOf(coeffs, N+1);
        // set g(x) = x^N − 1
        IntegerPolynomial g = new IntegerPolynomial(N+1);
        g.coeffs[0] = -1;
        g.coeffs[N] = 1;
        while (true) {
            while (f.coeffs[0] == 0) {
                for (int i=1; i<=N; i++) {
                    f.coeffs[i-1] = f.coeffs[i];   // f(x) = f(x) / x
                    c.coeffs[N+1-i] = c.coeffs[N-i];   // c(x) = c(x) * x
                }
                f.coeffs[N] = 0;
                c.coeffs[0] = 0;
                k++;
                if (f.equalsZero())
                    return null;   // not invertible
            }
            if (f.equalsAbsOne())
                break;
            if (f.degree() < g.degree()) {
                // exchange f and g
                IntegerPolynomial temp = f;
                f = g;
                g = temp;
                // exchange b and c
                temp = b;
                b = c;
                c = temp;
            }
            if (f.coeffs[0] == g.coeffs[0]) {
                f.sub(g, 3);
                b.sub(c, 3);
            }
            else {
                f.add(g, 3);
                b.add(c, 3);
            }
        }
        
        if (b.coeffs[N] != 0)
            return null;
        // Fp(x) = [+-] x^(N-k) * b(x)
        IntegerPolynomial Fp = new IntegerPolynomial(N);
        int j = 0;
        k %= N;
        for (int i=N-1; i>=0; i--) {
            j = i - k;
            if (j < 0)
                j += N;
            Fp.coeffs[j] = f.coeffs[0] * b.coeffs[i];
        }
        
        Fp.ensurePositive(3);
        return Fp;
    }
    
    /**
     * Resultant of this polynomial with <code>x^n-1</code>.<br/>
     * @return <code>(rho, res)</code> satisfying <code>res = rho*this + t*(x^n-1)</code> for some integer <code>t</code>.
     */
    Resultant resultant() {
        int N = coeffs.length;
        
        // upper bound for resultant(f, g) = ||f, 2||^deg(f) * ||g, 2||^deg(g) = squaresum(f)^(deg(f)/2) * 2^(N/2) because g(x)=x^N-1
        // see http://jondalon.mathematik.uni-osnabrueck.de/staff/phpages/brunsw/CompAlg.pdf chapter 3
        BigInteger max = squareSum().pow((degree()+1)/2);
        max = max.multiply(BigInteger.valueOf(2).pow((N+1)/2));
        BigInteger max2 = max.multiply(BigInteger.valueOf(2));
        BigInteger pProd = ONE;
        Iterator<BigInteger> primes = BIGINT_PRIMES.iterator();
        
        BigInteger res = ONE;
        BigIntPolynomial rhoP = new BigIntPolynomial(N);
        rhoP.coeffs[0] = ONE;
        BigInteger prime = BigInteger.valueOf(10000);
        while (pProd.compareTo(max2) < 0) {
            if (primes.hasNext())
                prime = primes.next();
            else
                prime = prime.nextProbablePrime();
            Resultant crr = resultant(prime.intValue());
            
            BigInteger temp = pProd.multiply(prime);
            BigIntEuclidean er = BigIntEuclidean.calculate(prime, pProd);
            
            res = res.multiply(er.x.multiply(prime));
            BigInteger res2 = crr.res.multiply(er.y.multiply(pProd));
            res = res.add(res2).mod(temp);
            
            rhoP.mult(er.x.multiply(prime));
            BigIntPolynomial rho = crr.rho;
            rho.mult(er.y.multiply(pProd));
            rhoP.add(rho);
            rhoP.mod(temp);
            pProd = temp;
        }
        
        BigInteger pProd2 = pProd.divide(BigInteger.valueOf(2));
        BigInteger pProd2n = pProd2.negate();
        
        res = res.mod(pProd);
        if (res.compareTo(pProd2) > 0)
            res = res.subtract(pProd);
        if (res.compareTo(pProd2n) < 0)
            res = res.add(pProd);
        
        rhoP.mod(pProd);
        for (int i=0; i<N; i++) {
            BigInteger c = rhoP.coeffs[i];
            if (c.compareTo(pProd2) > 0)
                rhoP.coeffs[i] = c.subtract(pProd);
            if (c.compareTo(pProd2n) < 0)
                rhoP.coeffs[i] = c.add(pProd);
        }

        return new Resultant(rhoP, res);
    }
        
    /**
     * Resultant of this polynomial with <code>x^n-1 mod p</code>.<br/>
     * @return <code>(rho, res)</code> satisfying <code>res = rho*this + t*(x^n-1) mod p</code> for some integer <code>t</code>.
     */
    Resultant resultant(int p) {
        // Add a coefficient as the following operations involve polynomials of degree deg(f)+1
        int[] fcoeffs = Arrays.copyOf(coeffs, coeffs.length+1);
        IntegerPolynomial f = new IntegerPolynomial(fcoeffs);
        int N = fcoeffs.length;
        
        IntegerPolynomial a = new IntegerPolynomial(N);
        a.coeffs[0] = -1;
        a.coeffs[N-1] = 1;
        IntegerPolynomial b = new IntegerPolynomial(f.coeffs);
        IntegerPolynomial v1 = new IntegerPolynomial(N);
        IntegerPolynomial v2 = new IntegerPolynomial(N);
        v2.coeffs[0] = 1;
        int da = N - 1;
        int db = b.degree();
        int ta = da;
        int c = 0;
        int r = 1;
        while (db > 0) {
            c = Util.invert(b.coeffs[db], p);
            c = (c * a.coeffs[da]) % p;
            a.multShiftSub(b, c, da-db, p);
            v1.multShiftSub(v2, c, da-db, p);
            
            da = a.degree();
            if (da < db) {
                r *= Util.pow(b.coeffs[db], ta-da, p);
                r %= p;
                if (ta%2==1 && db%2==1)
                    r = (-r) % p;
                IntegerPolynomial temp = a;
                a = b;
                b = temp;
                int tempdeg = da;
                da = db;
                temp = v1;
                v1 = v2;
                v2 = temp;
                ta = db;
                db = tempdeg;
            }
        }
        r *= Util.pow(b.coeffs[0], da, p);
        r %= p;
        c = Util.invert(b.coeffs[0], p);
        v2.mult(c);
        v2.mod(p);
        v2.mult(r);
        v2.mod(p);
        
        // drop the highest coefficient so #coeffs matches the original input
        v2.coeffs = Arrays.copyOf(v2.coeffs, v2.coeffs.length-1);
        return new Resultant(new BigIntPolynomial(v2), BigInteger.valueOf(r));
    }
    
    /**
     * Computes <code>b*c*(x^k) mod p</code> and stores the result in this polynomial.
     * @param b
     * @param c
     * @param k
     * @param p
     */
    private void multShiftSub(IntegerPolynomial b, int c, int k, int p) {
        int N = coeffs.length;
        for (int i=k; i<N; i++)
            coeffs[i] = (coeffs[i]-b.coeffs[i-k]*c) % p;
    }
    
    /**
     * Adds the squares of all coefficients.
     * @return the sum of squares
     */
    private BigInteger squareSum() {
        BigInteger sum = ZERO;
        for (int i=0; i<coeffs.length; i++)
            sum = sum.add(BigInteger.valueOf(coeffs[i]*coeffs[i]));
        return sum;
    }
    
    /**
     * Returns the degree of the polynomial
     * @return the degree
     */
    int degree() {
        int degree = coeffs.length - 1;
        while (degree>0 && coeffs[degree]==0)
            degree--;
        return degree;
    }
    
    /**
     * Adds another polynomial which can have a different number of coefficients,
     * and takes the coefficient values mod <code>modulus</code>.
     * @param b another polynomial
     */
    void add(IntegerPolynomial b, int modulus) {
        add(b);
        mod(modulus);
    }
    
    /**
     * Adds another polynomial which can have a different number of coefficients.
     * @param b another polynomial
     */
    void add(IntegerPolynomial b) {
        if (b.coeffs.length > coeffs.length)
            coeffs = Arrays.copyOf(coeffs, b.coeffs.length);
        for (int i=0; i<b.coeffs.length; i++)
            coeffs[i] += b.coeffs[i];
    }
    
    /**
     * Subtracts another polynomial which can have a different number of coefficients,
     * and takes the coefficient values mod <code>modulus</code>.
     * @param b another polynomial
     */
    void sub(IntegerPolynomial b, int modulus) {
        sub(b);
        mod(modulus);
    }
    
    /**
     * Subtracts another polynomial which can have a different number of coefficients.
     * @param b another polynomial
     */
    void sub(IntegerPolynomial b) {
        if (b.coeffs.length > coeffs.length)
            coeffs = Arrays.copyOf(coeffs, b.coeffs.length);
        for (int i=0; i<b.coeffs.length; i++)
            coeffs[i] -= b.coeffs[i];
    }
    
    /**
     * Subtracts a <code>int</code> from each coefficient. Does not return a new polynomial but modifies this polynomial.
     * @param b
     */
    void sub(int b) {
        for (int i=0; i<coeffs.length; i++)
            coeffs[i] -= b;
    }
    
    /**
     * Multiplies each coefficient by a <code>int</code>. Does not return a new polynomial but modifies this polynomial.
     * @param factor
     */
    void mult(int factor) {
        for (int i=0; i<coeffs.length; i++)
            coeffs[i] *= factor;
    }
    
    /**
     * Multiplies each coefficient by a 2 and applies a modulus. Does not return a new polynomial but modifies this polynomial.
     * @param modulus a modulus
     */
    private void mult2(int modulus) {
        for (int i=0; i<coeffs.length; i++) {
            coeffs[i] *= 2;
            coeffs[i] %= modulus;
        }
    }
    
    /**
     * Multiplies each coefficient by a 2 and applies a modulus. Does not return a new polynomial but modifies this polynomial.
     * @param modulus a modulus
     */
    void mult3(int modulus) {
        for (int i=0; i<coeffs.length; i++) {
            coeffs[i] *= 3;
            coeffs[i] %= modulus;
        }
    }
    
    /**
     * Divides each coefficient by <code>k</code> and rounds to the nearest integer. Does not return a new polynomial but modifies this polynomial.
     * @param k the divisor
     */
    void div(int k) {
        int k2 = (k+1) / 2;
        for (int i=0; i<coeffs.length; i++) {
            coeffs[i] += coeffs[i]>0 ? k2 : -k2;
            coeffs[i] /= k;
        }
    }
    
    /**
     * Takes each coefficient modulo 3 such that all coefficients are between -1 and 1.
     */
    void mod3() {
        for (int i=0; i<coeffs.length; i++) {
            coeffs[i] %= 3;
            if (coeffs[i] > 1)
                coeffs[i] -= 3;
            if (coeffs[i] < -1)
                coeffs[i] += 3;
        }
    }
    
    /**
     * Ensures all coefficients are between 0 and <code>modulus-1</code>
     * @param modulus a modulus
     */
    void modPositive(int modulus) {
        mod(modulus);
        ensurePositive(modulus);
    }
    
    /** Reduces all coefficients to the interval [-modulus/2, modulus/2) */
    void modCenter(int modulus) {
        mod(modulus);
        for (int j=0;j<coeffs.length;j++){
            while (coeffs[j] < modulus/2)
                coeffs[j] += modulus;
            while (coeffs[j] >= modulus/2)
                coeffs[j]-=modulus;
        }
    }
    
    /**
     * Takes each coefficient modulo <code>modulus</code>.
     */
    void mod(int modulus) {
        for (int i=0; i<coeffs.length; i++)
            coeffs[i] %= modulus;
    }
    
    /**
     * Adds <code>modulus</code> until all coefficients are above 0.
     * @param modulus a modulus
     */
    void ensurePositive(int modulus) {
        for (int i=0; i<coeffs.length; i++)
            while (coeffs[i] < 0)
                coeffs[i] += modulus;
    }
    
    /**
     * Computes the centered euclidean norm of the polynomial.
     * @param q a modulus
     * @return the centered norm
     */
    long centeredNormSq(int q) {
        int N = coeffs.length;
        IntegerPolynomial p = clone();
        p.shiftGap(q);
        
        long sum = 0;
        long sqSum = 0;
        for (int c: p.coeffs) {
            sum += c;
            sqSum += c * c;
        }
        
        long centeredNormSq = sqSum - sum*sum/N;
        return centeredNormSq;
    }
    
    /**
     * Shifts all coefficients so the largest gap is centered around <code>-q/2</code>.
     * @param q a modulus
     */
    void shiftGap(int q) {
        modCenter(q);
        
        int[] sorted = coeffs.clone();
        Arrays.sort(sorted);
        int maxrange = 0;
        int maxrangeStart = 0;
        for (int i=0; i<sorted.length-1; i++) {
            int range = sorted[i+1] - sorted[i];
            if (range > maxrange) {
                maxrange = range;
                maxrangeStart = sorted[i];
            }
        }
        
        int pmin = sorted[0];
        int pmax = sorted[sorted.length-1];
        
        int j = q - pmax + pmin;
        int shift;
        if (j > maxrange)
            shift = (pmax+pmin) / 2;
        else
            shift = maxrangeStart + maxrange/2 + q/2;
        
        sub(shift);
    }
    
    /**
     * Shifts the values of all coefficients to the interval <code>[-q/2, q/2]</code>.
     * @param q a modulus
     */
    void center0(int q) {
        for (int i=0; i<coeffs.length; i++) {
            while (coeffs[i] < -q/2)
                coeffs[i] += q;
            while (coeffs[i] > q/2)
                coeffs[i] -= q;
        }
    }
    
    /**
     * Returns the sum of all coefficients, i.e. evaluates the polynomial at 0.
     * @return the sum of all coefficients
     */
    int sumCoeffs() {
        int sum = 0;
        for (int i=0; i<coeffs.length; i++)
            sum += coeffs[i];
        return sum;
    }
    
    /**
     * Tests if <code>p(x) = 0</code>.
     * @return true iff all coefficients are zeros
     */
    private boolean equalsZero() {
        for (int i=0; i<coeffs.length; i++)
            if (coeffs[i] != 0)
                return false;
        return true;
    }
    
    /**
     * Tests if <code>p(x) = 1</code>.
     * @return true iff all coefficients are equal to zero, except for the lowest coefficient which must equal 1
     */
    boolean equalsOne() {
        for (int i=1; i<coeffs.length; i++)
            if (coeffs[i] != 0)
                return false;
        return coeffs[0] == 1;
    }
    
    /**
     * Tests if <code>|p(x)| = 1</code>.
     * @return true iff all coefficients are equal to zero, except for the lowest coefficient which must equal 1 or -1
     */
    private boolean equalsAbsOne() {
        for (int i=1; i<coeffs.length; i++)
            if (coeffs[i] != 0)
                return false;
        return Math.abs(coeffs[0]) == 1;
    }
    
    /**
     * Counts the number of coefficients equal to an integer
     * @param value an integer
     * @return the number of coefficients equal to <code>value</code>
     */
    int count(int value) {
        int count = 0;
        for (int coeff: coeffs)
            if (coeff == value)
                count++;
        return count;
    }
    
    /**
     * Multiplication by <code>X</code> in <code>Z[X]/Z[X^n-1]</code>.
     */
    void rotate1() {
        int clast = coeffs[coeffs.length-1];
        for (int i=coeffs.length-1; i>0; i--)
            coeffs[i] = coeffs[i-1];
        coeffs[0] = clast;
    }
    
   public void clear() {
        for (int i=0; i<coeffs.length; i++)
            coeffs[i] = 0;
    }
    
    @Override
    public IntegerPolynomial clone() {
        return new IntegerPolynomial(coeffs.clone());
    }
    
    @Override
    public boolean equals(Object obj) {
        if (obj instanceof IntegerPolynomial)
            return Arrays.equals(coeffs, ((IntegerPolynomial)obj).coeffs);
        else
            return false;
    }
}