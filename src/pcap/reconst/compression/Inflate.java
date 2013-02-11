/*
 * Author: Manoj Bharadwaj
 */

package pcap.reconst.compression;

import java.io.ByteArrayOutputStream;
import java.util.zip.Inflater;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class Inflate implements Unzip {
	private static Log log = LogFactory.getLog(Inflate.class);

	private byte[] input;
	private Dict dict;

	public Inflate(byte[] input, Dict dict) {
		this.input = input;
		this.dict = dict;
	}

	@Override
	public byte[] unzip() {
		Inflater inflater = new Inflater();

		byte[] output = new byte[100];
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		int compressedDataLength;
		inflater.setInput(input);
		try {
			compressedDataLength = inflater.inflate(output);
			if (compressedDataLength == 0 && inflater.needsDictionary()) {
				if (dict != null) {
					inflater.setDictionary(dict.getDict());
				}
				while (true) {
					compressedDataLength = inflater.inflate(output);
					if (compressedDataLength == 0) {
						break;
					}
					baos.write(output, 0, compressedDataLength);
					if (compressedDataLength != output.length) {
						break;
					}
				}
			} else {
				baos.write(output, 0, compressedDataLength);
				while (true) {
					compressedDataLength = inflater.inflate(output);
					if (compressedDataLength == 0) {
						break;
					}
					baos.write(output, 0, compressedDataLength);
					if (compressedDataLength != output.length) {
						break;
					}
				}
			}
		} catch (Exception e) {
			if (log.isDebugEnabled()) {
				log.debug(e);
			}
			inflater.end();
		}
		inflater.end();
		return baos.toByteArray();
	}
}