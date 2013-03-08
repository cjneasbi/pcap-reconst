/*
 * Author: Manoj Bharadwaj
 */
package pcap.reconst.tcp;

import java.util.Map;


public interface Reconstructor {
	Map<TcpConnection, TcpReassembler> reconstruct(String filename)
			throws Exception;
}