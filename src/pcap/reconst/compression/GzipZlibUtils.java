/*
 * Author: Manoj Bharadwaj
 */

package pcap.reconst.compression;

import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class GzipZlibUtils {

	private static Log log = LogFactory.getLog(GzipZlibUtils.class);

	public static Dict dict = loadDict("pcap/pcap/dict.txt");

	public static Dict loadDict(String name) {
		byte[] bytes = null;
		try {
			InputStream bf = GzipZlibUtils.class.getClassLoader()
					.getResourceAsStream(name);
			if (bf == null) {
				bf = ClassLoader.getSystemResourceAsStream(name);
			}
			if (bf == null) {
				return null;
			}
			int totallength = 0;
			byte[] readedtemp = new byte[1024];
			try {
				int truelen;
				while ((truelen = bf.read(readedtemp, 0, readedtemp.length)) != -1) {
					totallength += truelen;
					if (totallength - truelen > 0) {
						byte[] newReaded = new byte[totallength];
						System.arraycopy(bytes, 0, newReaded, 0, totallength
								- truelen);
						bytes = newReaded;
					} else {
						bytes = new byte[truelen];
					}

					System.arraycopy(readedtemp, 0, bytes, totallength
							- truelen, truelen);
				}
			} catch (IOException e) {
				if (log.isErrorEnabled()) {
					log.error("", e);
				}
				return null;
			}
		} catch (Exception e) {
			if (log.isErrorEnabled()) {
				log.error("", e);
			}
		}
		return new Dict(bytes);
	}

	public static byte[] compress(CompressionType compressionType, byte[] input) {
		return new CompressImpl(compressionType, input, dict).compress();
	}

	public static byte[] uncompress(CompressionType compressionType,
			byte[] input) {
		return new UncompressImpl(compressionType, input, dict).uncompress();
	}

	/*
	 * public static byte[] deflate(String originalText) { return
	 * deflate(originalText.getBytes(), dict); }
	 */

	/*
	 * public static byte[] deflate(byte[] input, Dict dict) { return new
	 * Deflate(input).zip(); }
	 * 
	 * public static byte[] inflate(byte[] originalByte) throws Exception {
	 * return new Inflate(originalByte).unzip(); }
	 */

	/*
	 * public static byte[] gzip(byte[] input) { Zip zip = new GZip(input);
	 * return zip.zip(); }
	 * 
	 * public static byte[] gunzip(byte[] inputBytes) { Unzip unzip = new
	 * Gunzip(inputBytes); return unzip.unzip(); }
	 */

}
