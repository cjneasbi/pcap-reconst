/*
 * Author(s): Manoj Bharadwaj, Chris Neasbitt
 */

package pcap.reconst.decoder;

import java.io.FileInputStream;
import java.io.FileNotFoundException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import pcap.reconst.Utils;
import pcap.reconst.beans.DecodedData;
import pcap.reconst.beans.Headers;
import pcap.reconst.beans.TimestampPair;
import pcap.reconst.compression.CompressionType;
import pcap.reconst.compression.GzipZlibUtils;

public class DecoderImpl implements Decoder {

	private static Log log = LogFactory.getLog(DecoderImpl.class);

	@Override
	public DecodedData decode(byte[] streamToBeDecoded, Headers headers,
			TimestampPair ts) {
		if (log.isDebugEnabled()) {
			log.debug("length is [" + streamToBeDecoded.length + "], data is ["
					+ new String(streamToBeDecoded) + "]");
		}
		Utils.prettyPrintHex(streamToBeDecoded);

		if (headers != null) {
			CompressionType compressionType = headers.getCompressionType();
			if (Utils.isCompressed(compressionType)) {
				streamToBeDecoded = GzipZlibUtils.uncompress(compressionType,
						streamToBeDecoded);
				if (log.isDebugEnabled()) {
					log.debug("after gunzip: length is ["
							+ streamToBeDecoded.length + "], data is ["
							+ new String(streamToBeDecoded) + "]");
				}
			}
		}
		return new DecodedData(streamToBeDecoded, headers, ts);
	}

	public static void main(String[] args) throws FileNotFoundException {
		DecoderImpl decoder = new DecoderImpl();
		FileInputStream fis = new FileInputStream("c:\\wireshark\\http.reconst");
		byte[] byteArray = Utils.getByteArray(fis);
		Headers headers = new Headers();
		headers.addHeader(Headers.CONTENT_ENCODING, Headers.DEFLATE);
		decoder.decode(byteArray, headers, new TimestampPair(0, 0));
	}
}
