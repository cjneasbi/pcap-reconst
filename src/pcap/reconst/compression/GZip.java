/*
 * Author: Manoj Bharadwaj
 */

package pcap.reconst.compression;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.GZIPOutputStream;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class GZip implements Zip {
	private static Log log = LogFactory.getLog(GZip.class);

	private byte[] input;

	public GZip(byte[] input) {
		this.input = input;
	}

	@Override
	public byte[] zip() {
		byte[] zipped = new byte[0];
		ByteArrayOutputStream baos = null;
		BufferedOutputStream bos = null;
		try {
			baos = new ByteArrayOutputStream();
			bos = new BufferedOutputStream(new GZIPOutputStream(baos));
			bos.write(input);
			zipped = baos.toByteArray();
			// bos.close();
			// baos.close();
		} catch (IOException ioe) {
			if (log.isErrorEnabled()) {
				log.error("", ioe);
			}
		} finally {
			if (baos != null) {
				try {
					baos.close();
				} catch (IOException e) {
					if (log.isErrorEnabled()) {
						log.error("", e);
					}
				}
			}
			if (bos != null) {
				try {
					bos.close();
				} catch (IOException e) {
					if (log.isErrorEnabled()) {
						log.error("", e);
					}
				}
			}
		}
		return zipped;
	}
}
