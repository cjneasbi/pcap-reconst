/*
 * Author(s): Manoj Bharadwaj, Chris Neasbitt
 */

package pcap.reconst.decoder;

import org.apache.http.HttpEntity;

public interface Decoder {
	public HttpEntity decodeEntity(HttpEntity ent) throws Exception;
}
