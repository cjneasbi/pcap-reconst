/*
 * Author: Manoj Bharadwaj
 */
package pcap.reconst.reconstructor;

import pcap.reconst.beans.TcpConnection;

import java.util.Map;

public interface Reconstructor {
    Map<TcpConnection, TcpReassembler> reconstruct(String filename) throws Exception;
}