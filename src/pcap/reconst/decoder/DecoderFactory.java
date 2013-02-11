/*
 * Author: Manoj Bharadwaj
 */

package pcap.reconst.decoder;

public class DecoderFactory {
	public static Decoder getDecoder() {
		return new DecoderImpl();
	}
}
