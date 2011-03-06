package net.sf.ntru;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class IntEuclideanTest {
    
    @Test
    public void testCalculate() {
        IntEuclidean r = IntEuclidean.calculate(120, 23);
        assertEquals(-9, r.x);
        assertEquals(47, r.y);
        assertEquals(1, r.gcd);
        
        r = IntEuclidean.calculate(126, 231);
        assertEquals(2, r.x);
        assertEquals(-1, r.y);
        assertEquals(21, r.gcd);
    }
}