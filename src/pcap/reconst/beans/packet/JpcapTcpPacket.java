/*
 * Author(s): Manoj Bharadwaj, Chris Neasbitt
 */

package pcap.reconst.beans.packet;

import java.net.InetAddress;

import jpcap.packet.TCPPacket;

public class JpcapTcpPacket implements TcpPacket {
	private TCPPacket tcpPacket;

	public JpcapTcpPacket(TCPPacket tcpPacket) {
		this.tcpPacket = tcpPacket;
	}

	@Override
	public InetAddress getSourceIP() {
		return tcpPacket.src_ip;
	}

	@Override
	public int getSourcePort() {
		return tcpPacket.src_port;
	}

	@Override
	public InetAddress getDestinationIP() {
		return tcpPacket.dst_ip;
	}

	@Override
	public int getDestinationPort() {
		return tcpPacket.dst_port;
	}

	@Override
	public int getCaptureLength() {
		return tcpPacket.caplen;
	}

	@Override
	public int getLength() {
		return tcpPacket.len;
	}

	@Override
	public int getHeaderLength() {
		return tcpPacket.header.length;
	}

	@Override
	public int getDataLength() {
		return tcpPacket.data.length;
	}

	@Override
	public long getSequence() {
		return tcpPacket.sequence;
	}

	@Override
	public long getAckNum() {
		return tcpPacket.ack_num;
	}

	@Override
	public byte[] getData() {
		return tcpPacket.data;
	}

	@Override
	public boolean getSyn() {
		return tcpPacket.syn;
	}

	@Override
	public boolean getAck() {
		return tcpPacket.ack;
	}

	@Override
	public boolean getFin() {
		return tcpPacket.fin;
	}

	@Override
	public boolean getPsh() {
		return tcpPacket.psh;
	}

	@Override
	public long getTimestampSec() {
		return tcpPacket.sec;
	}

	@Override
	public long getTimestampUSec() {
		return tcpPacket.usec;
	}

	@Override
	public String toString() {
		return "sequence=" + getSequence() + " ack_num=" + getAckNum()
				+ " length=" + getLength() + " dataLength=" + getDataLength()
				+ " synFlag=" + getSyn() + " " + getSourceIP() + " srcPort="
				+ getSourcePort() + " " + getDestinationIP() + " dstPort="
				+ getDestinationPort() + " timestamp=" + getTimestampSec();
	}
}
