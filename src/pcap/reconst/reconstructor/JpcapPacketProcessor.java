/*
 * Author(s): Manoj Bharadwaj, Chris Neasbitt
 */

package pcap.reconst.reconstructor;

import jpcap.PacketReceiver;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;
import pcap.reconst.beans.packet.JpcapTcpPacket;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class JpcapPacketProcessor implements PacketReceiver {
	private static Log log = LogFactory.getLog(JpcapPacketProcessor.class);
	
    int packetNumber = 0;
    private PacketReassembler packetReassembler;

    public JpcapPacketProcessor(PacketReassembler packetReassembler) {
        this.packetReassembler = packetReassembler;
    }

    public int getTotalNumberOfPackets() {
        return packetNumber;
    }

    //this method is called every time Jpcap captures a packet
    public void receivePacket(Packet packet) {
        packetNumber++;
        if(log.isDebugEnabled()){
        	log.debug("processing #" + packetNumber  + " " + packet);
        }
        packetReassembler.reassemble(new JpcapTcpPacket((TCPPacket) packet));
    }
}

