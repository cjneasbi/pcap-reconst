/*
 * Author: Manoj Bharadwaj
 */
package pcap.reconst.reconstructor;

import java.util.Map;

import pcap.reconst.beans.TcpConnection;

public interface Reconstructor {
	Map<TcpConnection, TcpReassembler> reconstruct(String filename)
			throws Exception;
}