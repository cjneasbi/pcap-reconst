/*
 * Author: Manoj Bharadwaj
 */

package pcap.reconst.compression;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.GZIPInputStream;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class Gunzip implements Unzip {
	private static Log log = LogFactory.getLog(Gunzip.class);

	private byte[] input;

	public Gunzip(byte[] input) {
		this.input = input;
	}

	@Override
	public byte[] unzip() {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		GZIPInputStream gzipis = null;
		ByteArrayInputStream bais = null;

		try {
			byte[] buf = new byte[100];
			bais = new ByteArrayInputStream(input);
			gzipis = new GZIPInputStream(bais);
			int size;
			while ((size = gzipis.read(buf)) != -1) {
				baos.write(buf, 0, size);
			}
		} catch (Exception ex) {
			if (log.isErrorEnabled()) {
				log.error("", ex);
			}
		} finally {
			if (bais != null) {
				try {
					bais.close();
				} catch (IOException e) {
					if (log.isErrorEnabled()) {
						log.error("", e);
					}
				}
			}
			if (gzipis != null) {
				try {
					gzipis.close();
				} catch (IOException e) {
					if (log.isErrorEnabled()) {
						log.error("", e);
					}
				}
			}
			try {
				baos.close();
			} catch (IOException e) {
				if (log.isErrorEnabled()) {
					log.error("", e);
				}
			}
		}

		byte[] bytesToReturn = baos.toByteArray();
		if (bytesToReturn.length == 0) {
			return input;
		} else {
			return bytesToReturn;
		}
	}
}