/*
 * Author(s): Manoj Bharadwaj, Chris Neasbitt
 */

package pcap.reconst.decoder;

import pcap.reconst.beans.DecodedData;
import pcap.reconst.beans.Headers;
import pcap.reconst.beans.TimestampPair;

public interface Decoder {
    public DecodedData decode(byte[] encodedStream, Headers headers, TimestampPair ts);
}
