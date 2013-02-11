/*
 * Author: Manoj Bharadwaj
 */

package pcap.reconst.compression;

import java.util.Arrays;

public enum CompressionType {
    gzip, deflate;

    public static boolean isValid(CompressionType compressionType) {
        return Arrays.asList(CompressionType.values()).contains(compressionType);
    }

    public static boolean isValid(String compressionTypeString) {
        for (CompressionType compressionType : CompressionType.values()) {
            if (compressionTypeString.equals(compressionType.toString())) {
                return true;
            }
        }
        return false;
    }
}
