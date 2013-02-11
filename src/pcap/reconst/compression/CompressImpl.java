/*
 * Author: Manoj Bharadwaj
 */

package pcap.reconst.compression;

public class CompressImpl implements Compress {

    private CompressionType compressionType;
    private byte[] input;
    private Dict dict;

    public CompressImpl(CompressionType compressionType, byte[] input, Dict dict) {
        this.compressionType = compressionType;
        this.input = input;
        this.dict = dict;
    }

    public byte[] compress() {
        byte[] compressed = input;
        if (CompressionType.gzip == compressionType) {
            compressed = new GZip(input).zip();
        } else if (CompressionType.deflate == compressionType) {
            compressed = new Deflate(input, dict).zip();
        }
        return compressed;
    }
}
