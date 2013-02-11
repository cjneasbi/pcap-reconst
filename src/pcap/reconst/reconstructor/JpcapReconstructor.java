/*
 * Author(s): Manoj Bharadwaj, Chris Neasbitt
 */

package pcap.reconst.reconstructor;

import jpcap.JpcapCaptor;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import pcap.reconst.beans.TcpConnection;

import java.util.Map;

public class JpcapReconstructor implements Reconstructor {
	private static Log log = LogFactory.getLog(JpcapReconstructor.class);
	
    private PacketReassembler packetReassembler;

    public JpcapReconstructor(PacketReassembler packetReassembler) {
        this.packetReassembler = packetReassembler;
    }

    public Map<TcpConnection, TcpReassembler> reconstruct(String filename) throws Exception {
    	if(log.isDebugEnabled()){
    		log.debug("reconstructing " + filename + " ...");
    	}
        JpcapCaptor captor = JpcapCaptor.openFile(filename);
        captor.setFilter("tcp", true);
        JpcapPacketProcessor jpcapPacketProcessor = new JpcapPacketProcessor(packetReassembler);
        captor.processPacket(-1, jpcapPacketProcessor);
        captor.close();
        return packetReassembler.getReassembledPackets();
    }

}
