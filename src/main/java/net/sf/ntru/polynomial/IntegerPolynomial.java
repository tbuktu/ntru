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

import static java.math.BigInteger.ONE;
import static java.math.BigInteger.ZERO;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;

import net.sf.ntru.exception.NtruException;
import net.sf.ntru.util.ArrayEncoder;
import net.sf.ntru.util.Util;

/**
 * A polynomial with <code>int</code> coefficients.<br/>
 * Some methods (like <code>add</code>) change the polynomial, others (like <code>mult</code>) do
 * not but return the result as a new polynomial.
 */
public class IntegerPolynomial implements Polynomial {
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
        12553, 12569, 12577, 12583, 12589, 12601, 12611, 12613, 12619, 12637, 
        12641, 12647, 12653, 12659, 12671, 12689, 12697, 12703, 12713, 12721, 
        12739, 12743, 12757, 12763, 12781, 12791, 12799, 12809, 12821, 12823, 
        12829, 12841, 12853, 12889, 12893, 12899, 12907, 12911, 12917, 12919, 
        12923, 12941, 12953, 12959, 12967, 12973, 12979, 12983, 13001, 13003, 
        13007, 13009, 13033, 13037, 13043, 13049, 13063, 13093, 13099, 13103, 
        13109, 13121, 13127, 13147, 13151, 13159, 13163, 13171, 13177, 13183, 
        13187, 13217, 13219, 13229, 13241, 13249, 13259, 13267, 13291, 13297, 
        13309, 13313, 13327, 13331, 13337, 13339, 13367, 13381, 13397, 13399, 
        13411, 13417, 13421, 13441, 13451, 13457, 13463, 13469, 13477, 13487, 
        13499, 13513, 13523, 13537, 13553, 13567, 13577, 13591, 13597, 13613, 
        13619, 13627, 13633, 13649, 13669, 13679, 13681, 13687, 13691, 13693, 
        13697, 13709, 13711, 13721, 13723, 13729, 13751, 13757, 13759, 13763, 
        13781, 13789, 13799, 13807, 13829, 13831, 13841, 13859, 13873, 13877, 
        13879, 13883, 13901, 13903, 13907, 13913, 13921, 13931, 13933, 13963, 
        13967, 13997, 13999, 14009, 14011, 14029, 14033, 14051, 14057, 14071, 
        14081, 14083, 14087, 14107, 14143, 14149, 14153, 14159, 14173, 14177, 
        14197, 14207, 14221, 14243, 14249, 14251, 14281, 14293, 14303, 14321, 
        14323, 14327, 14341, 14347, 14369, 14387, 14389, 14401, 14407, 14411, 
        14419, 14423, 14431, 14437, 14447, 14449, 14461, 14479, 14489, 14503, 
        14519, 14533, 14537, 14543, 14549, 14551, 14557, 14561, 14563, 14591, 
        14593, 14621, 14627, 14629, 14633, 14639, 14653, 14657, 14669, 14683, 
        14699, 14713, 14717, 14723, 14731, 14737, 14741, 14747, 14753, 14759, 
        14767, 14771, 14779, 14783, 14797, 14813, 14821, 14827, 14831, 14843, 
        14851, 14867, 14869, 14879, 14887, 14891, 14897, 14923, 14929, 14939, 
        14947, 14951, 14957, 14969, 14983, 15013, 15017, 15031, 15053, 15061, 
        15073, 15077, 15083, 15091, 15101, 15107, 15121, 15131, 15137, 15139, 
        15149, 15161, 15173, 15187, 15193, 15199, 15217, 15227, 15233, 15241, 
        15259, 15263, 15269, 15271, 15277, 15287, 15289, 15299, 15307, 15313, 
        15319, 15329, 15331, 15349, 15359, 15361, 15373, 15377, 15383, 15391, 
        15401, 15413, 15427, 15439, 15443, 15451, 15461, 15467, 15473, 15493, 
        15497, 15511, 15527, 15541, 15551, 15559, 15569};
    private static final List<BigInteger> BIGINT_PRIMES;

    static {
        BIGINT_PRIMES = new ArrayList<BigInteger>();
        for (int p: PRIMES)
            BIGINT_PRIMES.add(BigInteger.valueOf(p));
    }
    
    public int[] coeffs;
    
    /**
     * Constructs a new polynomial with <code>N</code> coefficients initialized to 0.
     * @param N the number of coefficients
     */
    public IntegerPolynomial(int N) {
        coeffs = new int[N];
    }
    
    /**
     * Constructs a new polynomial with a given set of coefficients.
     * @param coeffs the coefficients
     */
    public IntegerPolynomial(int[] coeffs) {
        this.coeffs = coeffs;
    }
    
    /**
     * Constructs a <code>IntegerPolynomial</code> from a <code>BigIntPolynomial</code>. The two polynomials are independent of each other.
     * @param p the original polynomial
     */
    public IntegerPolynomial(BigIntPolynomial p) {
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
    public static IntegerPolynomial fromBinary3(byte[] data, int N) {
        return new IntegerPolynomial(ArrayEncoder.decodeMod3(data, N));
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
    public static IntegerPolynomial fromBinary(byte[] data, int N, int q) {
        return new IntegerPolynomial(ArrayEncoder.decodeModQ(data, N, q));
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
    public static IntegerPolynomial fromBinary(ByteBuffer buf, int N, int q) {
        return new IntegerPolynomial(ArrayEncoder.decodeModQ(buf, N, q));
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
    public static IntegerPolynomial fromBinary(InputStream is, int N, int q) throws IOException {
        return new IntegerPolynomial(ArrayEncoder.decodeModQ(is, N, q));
    }
    
    /**
     * Encodes a polynomial whose coefficients are between -1 and 1, to binary.
     * <code>coeffs[2*i]</code> and <code>coeffs[2*i+1]</code> must not both equal -1 for any integer </code>i<code>,
     * so this method is only safe to use with polynomials produced by <code>fromBinary3()</code>.
     * @return the encoded polynomial
     */
    public byte[] toBinary3() {
        return ArrayEncoder.encodeMod3(coeffs);
    }
    
    /**
     * Converts a polynomial whose coefficients are between -1 and 1, to binary.
     * @return the encoded polynomial
     */
    public byte[] toBinary3Arith() {
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
    public static IntegerPolynomial fromBinary3Arith(byte[] b, int N) {
        return new IntegerPolynomial(ArrayEncoder.decodeMod3Arith(b, N));
    }
    
    /**
     * Reads data produced by toBinary3Arith() from a byte buffer and converts it to a polynomial.
     * @param b a byte buffer
     * @param N number of coefficients
     * @return the decoded polynomial
     */
    public static IntegerPolynomial fromBinary3Arith(ByteBuffer buf, int N) {
        return new IntegerPolynomial(ArrayEncoder.decodeMod3Arith(buf, N));
    }
    
    /**
     * Reads data produced by toBinary3Arith() from an input stream and converts it to a polynomial.
     * @param b an input stream
     * @param N number of coefficients
     * @return the decoded polynomial
     */
    public static IntegerPolynomial fromBinary3Arith(InputStream is, int N) throws IOException {
        return new IntegerPolynomial(ArrayEncoder.decodeMod3Arith(is, N));
    }
    
    /**
     * Encodes a polynomial whose coefficients are between 0 and q, to binary. q must be a power of 2.
     * @param q
     * @return the encoded polynomial
     */
    public byte[] toBinary(int q) {
        return ArrayEncoder.encodeModQ(coeffs, q);
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
    
    @Override
    public BigIntPolynomial mult(BigIntPolynomial poly2) {
        return new BigIntPolynomial(this).mult(poly2);
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
    public IntegerPolynomial invertFq(int q) {
        int N = coeffs.length;
        int k = 0;
        IntegerPolynomial b = new IntegerPolynomial(N+1);
        b.coeffs[0] = 1;
        IntegerPolynomial c = new IntegerPolynomial(N+1);
        IntegerPolynomial f = new IntegerPolynomial(N+1);
        f.coeffs = Arrays.copyOf(coeffs, N+1);
        f.modPositive(2);
        // set g(x) = x^N − 1
        IntegerPolynomial g = new IntegerPolynomial(N+1);
        g.coeffs[0] = 1;
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
        
        return mod2ToModq(Fq, q);
    }
    
    /**
     * Computes the inverse mod q from the inverse mod 2
     * @param Fq
     * @param q
     * @return The inverse of this polynomial mod q
     */
    private IntegerPolynomial mod2ToModq(IntegerPolynomial Fq, int q) {
        if (Util.is64BitJVM() && q==2048) {
            LongPolynomial2 thisLong = new LongPolynomial2(this);
            LongPolynomial2 FqLong = new LongPolynomial2(Fq);
            int v = 2;
            while (v < q) {
                v *= 2;
                LongPolynomial2 temp = FqLong.clone();
                temp.mult2And(v-1);
                FqLong = thisLong.mult(FqLong).mult(FqLong);
                temp.subAnd(FqLong, v-1);
                FqLong = temp;
            }
            return FqLong.toIntegerPolynomial();
        }
        else {
            int v = 2;
            while (v < q) {
                v *= 2;
                IntegerPolynomial temp = new IntegerPolynomial(Arrays.copyOf(Fq.coeffs, Fq.coeffs.length));
                temp.mult2(v);
                Fq = mult(Fq, v).mult(Fq, v);
                temp.sub(Fq, v);
                Fq = temp;
            }
            return Fq;
        }
    }
    
    /**
     * Computes the inverse mod 3.
     * Returns <code>null</code> if the polynomial is not invertible.
     * @return a new polynomial
     */
    public IntegerPolynomial invertF3() {
        int N = coeffs.length;
        int k = 0;
        IntegerPolynomial b = new IntegerPolynomial(N+1);
        b.coeffs[0] = 1;
        IntegerPolynomial c = new IntegerPolynomial(N+1);
        IntegerPolynomial f = new IntegerPolynomial(N+1);
        f.coeffs = Arrays.copyOf(coeffs, N+1);
        f.modPositive(3);
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
    public Resultant resultant() {
        int N = coeffs.length;
        
        // upper bound for resultant(f, g) = ||f, 2||^deg(g) * ||g, 2||^deg(f) = squaresum(f)^(N/2) * 2^(deg(f)/2) because g(x)=x^N-1
        // see http://jondalon.mathematik.uni-osnabrueck.de/staff/phpages/brunsw/CompAlg.pdf chapter 3
        BigInteger max = squareSum().pow((N+1)/2);
        max = max.multiply(BigInteger.valueOf(2).pow((degree()+1)/2));
        BigInteger max2 = max.multiply(BigInteger.valueOf(2));
        Iterator<BigInteger> primes = BIGINT_PRIMES.iterator();
        
        // compute resultants modulo prime numbers
        LinkedList<Subresultant> subresultants = new LinkedList<Subresultant>();
        BigInteger prime = BigInteger.valueOf(10000);
        BigInteger pProd = ONE;
        while (pProd.compareTo(max2) < 0) {
            if (primes.hasNext())
                prime = primes.next();
            else
                prime = prime.nextProbablePrime();
            subresultants.add(resultant(prime.intValue()));
            pProd = pProd.multiply(prime);
        }
        
        // combine subresultants to obtain the resultant.
        // for efficiency, first combine all pairs of small subresultants to bigger subresultants,
        // then combine pairs of those, etc. until only one is left.
        while (subresultants.size() > 1) {
            Subresultant subres1 = subresultants.removeFirst();
            Subresultant subres2 = subresultants.removeFirst();
            Subresultant subres3 = Subresultant.combine(subres1, subres2);
            subresultants.addLast(subres3);
        }
        BigInteger res = subresultants.getFirst().res;
        BigIntPolynomial rhoP = subresultants.getFirst().rho;
        
        BigInteger pProd2 = pProd.divide(BigInteger.valueOf(2));
        BigInteger pProd2n = pProd2.negate();
        
        if (res.compareTo(pProd2) > 0)
            res = res.subtract(pProd);
        if (res.compareTo(pProd2n) < 0)
            res = res.add(pProd);
        
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
     * Multithreaded version of {@link #resultant()}.
     * @return <code>(rho, res)</code> satisfying <code>res = rho*this + t*(x^n-1)</code> for some integer <code>t</code>.
     */
    public Resultant resultantMultiThread() {
        int N = coeffs.length;
        
        // upper bound for resultant(f, g) = ||f, 2||^deg(g) * ||g, 2||^deg(f) = squaresum(f)^(N/2) * 2^(deg(f)/2) because g(x)=x^N-1
        // see http://jondalon.mathematik.uni-osnabrueck.de/staff/phpages/brunsw/CompAlg.pdf chapter 3
        BigInteger max = squareSum().pow((N+1)/2);
        max = max.multiply(BigInteger.valueOf(2).pow((degree()+1)/2));
        BigInteger max2 = max.multiply(BigInteger.valueOf(2));
        
        // compute resultants modulo prime numbers
        BigInteger prime = BigInteger.valueOf(10000);
        BigInteger pProd = ONE;
        LinkedBlockingQueue<Future<Subresultant>> resultantTasks = new LinkedBlockingQueue<Future<Subresultant>>();
        Iterator<BigInteger> primes = BIGINT_PRIMES.iterator();
        ExecutorService executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
        while (pProd.compareTo(max2) < 0) {
            if (primes.hasNext())
                prime = primes.next();
            else
                prime = prime.nextProbablePrime();
            Future<Subresultant> task = executor.submit(new SubresultantTask(prime.intValue()));
            resultantTasks.add(task);
            pProd = pProd.multiply(prime);
        }
        
        // combine subresultants to obtain the resultant.
        // for efficiency, first combine all pairs of small subresultants to bigger subresultants,
        // then combine pairs of those, etc. until only one is left.
        Subresultant overallResultant = null;
        while (!resultantTasks.isEmpty()) {
            try {
                Future<Subresultant> subres1 = resultantTasks.take();
                Future<Subresultant> subres2 = resultantTasks.poll();
                if (subres2 == null) {
                    // subres1 is the only one left
                    overallResultant = subres1.get();
                    break;
                }
                Future<Subresultant> newTask = executor.submit(new CombineTask(subres1.get(), subres2.get()));
                resultantTasks.add(newTask);
            } catch (Exception e) {
                throw new NtruException(e);
            }
        }
        executor.shutdown();
        BigInteger res = overallResultant.res;
        BigIntPolynomial rhoP = overallResultant.rho;
        
        BigInteger pProd2 = pProd.divide(BigInteger.valueOf(2));
        BigInteger pProd2n = pProd2.negate();
        
        if (res.compareTo(pProd2) > 0)
            res = res.subtract(pProd);
        if (res.compareTo(pProd2n) < 0)
            res = res.add(pProd);
        
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
    public Subresultant resultant(int p) {
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
        return new Subresultant(new BigIntPolynomial(v2), BigInteger.valueOf(r), BigInteger.valueOf(p));
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
    public void add(IntegerPolynomial b, int modulus) {
        add(b);
        mod(modulus);
    }
    
    /**
     * Adds another polynomial which can have a different number of coefficients.
     * @param b another polynomial
     */
    public void add(IntegerPolynomial b) {
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
    public void sub(IntegerPolynomial b, int modulus) {
        sub(b);
        mod(modulus);
    }
    
    /**
     * Subtracts another polynomial which can have a different number of coefficients.
     * @param b another polynomial
     */
    public void sub(IntegerPolynomial b) {
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
    public void mult(int factor) {
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
    public void mult3(int modulus) {
        for (int i=0; i<coeffs.length; i++) {
            coeffs[i] *= 3;
            coeffs[i] %= modulus;
        }
    }
    
    /**
     * Divides each coefficient by <code>k</code> and rounds to the nearest integer. Does not return a new polynomial but modifies this polynomial.
     * @param k the divisor
     */
    public void div(int k) {
        int k2 = (k+1) / 2;
        for (int i=0; i<coeffs.length; i++) {
            coeffs[i] += coeffs[i]>0 ? k2 : -k2;
            coeffs[i] /= k;
        }
    }
    
    /**
     * Takes each coefficient modulo 3 such that all coefficients are between -1 and 1.
     */
    public void mod3() {
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
    public void modPositive(int modulus) {
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
    public void ensurePositive(int modulus) {
        for (int i=0; i<coeffs.length; i++)
            while (coeffs[i] < 0)
                coeffs[i] += modulus;
    }
    
    /**
     * Computes the centered euclidean norm of the polynomial.
     * @param q a modulus
     * @return the centered norm
     */
    public long centeredNormSq(int q) {
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
    public void center0(int q) {
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
    public int sumCoeffs() {
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
    public int count(int value) {
        int count = 0;
        for (int coeff: coeffs)
            if (coeff == value)
                count++;
        return count;
    }
    
    /**
     * Multiplication by <code>X</code> in <code>Z[X]/Z[X^n-1]</code>.
     */
    public void rotate1() {
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
    public IntegerPolynomial toIntegerPolynomial() {
        return clone();
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
    
    /** Calls {@link IntegerPolynomial#resultant(int) */
    private class SubresultantTask implements Callable<Subresultant> {
        private int modulus;
        
        private SubresultantTask(int modulus) {
            this.modulus = modulus;
        }

        @Override
        public Subresultant call() {
            return resultant(modulus);
        }
    }
    
    /** Calls {@link IntegerPolynomial#combine(Subresultant, Subresultant) */
    private class CombineTask implements Callable<Subresultant> {
        private Subresultant subres1;
        private Subresultant subres2;

        private CombineTask(Subresultant subres1, Subresultant subres2) {
            this.subres1 = subres1;
            this.subres2 = subres2;
        }
        
        @Override
        public Subresultant call() {
            return Subresultant.combine(subres1, subres2);
        }
    }
}