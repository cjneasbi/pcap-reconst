/*
 * Author: Manoj Bharadwaj
 */

package pcap.reconst.compression;

public class UncompressImpl implements Uncompress {

	private CompressionType compressionType;
	private byte[] input;
	private Dict dict;

	public UncompressImpl(CompressionType compressionType, byte[] input,
			Dict dict) {
		this.compressionType = compressionType;
		this.input = input;
		this.dict = dict;
	}

	@Override
	public byte[] uncompress() {
		byte[] uncompressed = input;
		if (CompressionType.gzip == compressionType) {
			uncompressed = new Gunzip(input).unzip();
		} else if (CompressionType.deflate == compressionType) {
			uncompressed = new Inflate(input, dict).unzip();
		}
		return uncompressed;
	}
}