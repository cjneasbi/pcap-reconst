/*
 * Author: Manoj Bharadwaj
 */

package pcap.reconst.compression;

public class Dict {

    private byte[] input;

    public Dict(byte[] input) {
        this.input = input;
    }

    public byte[] getDict() {
        return input;
    }
}