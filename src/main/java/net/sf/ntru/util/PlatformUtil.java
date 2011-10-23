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

package net.sf.ntru.util;

public class PlatformUtil {
    private static volatile boolean IS_64_BITNESS_KNOWN;
    private static volatile boolean IS_64_BIT_JVM;

    /**
     * Takes an educated guess as to whether 64 bits are supported by the JVM.
     * @return <code>true</code> if 64-bit support detected, <code>false</code> otherwise
     */
    public static boolean is64BitJVM() {
        if (!IS_64_BITNESS_KNOWN) {
            String arch = System.getProperty("os.arch");
            String sunModel = System.getProperty("sun.arch.data.model");
            IS_64_BIT_JVM = "amd64".equals(arch) || "x86_64".equals(arch) || "ppc64".equals(arch) || "64".equals(sunModel);
            IS_64_BITNESS_KNOWN = true;
        }
        return IS_64_BIT_JVM;
    }
}