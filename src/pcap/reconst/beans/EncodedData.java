/*
 * Author(s): Manoj Bharadwaj, Chris Neasbitt
 */

package pcap.reconst.beans;

public class EncodedData extends InputData {
	public EncodedData(byte[] encodedBytes, Headers headers, TimestampPair ts) {
		super(encodedBytes, headers, ts);
	}
}
