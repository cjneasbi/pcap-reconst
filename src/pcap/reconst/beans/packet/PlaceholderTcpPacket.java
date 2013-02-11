/*
 * Author: Chris Neasbitt
 */

package pcap.reconst.beans.packet;

import java.net.InetAddress;

import pcap.reconst.beans.TcpConnection;

public class PlaceholderTcpPacket implements TcpPacket {
    private InetAddress sourceIP, destinationIP;
    private int sourcePort, destinationPort, length;
	private long sequence;
    
	
	public PlaceholderTcpPacket(TcpConnection conn, long sequence, long ackNum, int length){
		this(conn.getSrcIp(), conn.getSrcPort(), conn.getDstIp(), conn.getDstPort(), sequence, length);
	}
	
	public PlaceholderTcpPacket(InetAddress sourceIP, int sourcePort, InetAddress destinationIP, 
			int destinationPort, long sequence, int length){
		this.sourceIP = sourceIP;
		this.sourcePort = sourcePort;
		this.destinationIP = destinationIP;
		this.destinationPort = destinationPort;
		this.sequence = sequence;
		this.length = length;
	}
	
	public InetAddress getSourceIP() {
		return sourceIP;
	}

	public int getSourcePort() {
		return sourcePort;
	}

	public InetAddress getDestinationIP() {
		return destinationIP;
	}

	public int getDestinationPort() {
		return destinationPort;
	}

	//same as get length
	public int getCaptureLength() {
		return length;
	}

	public int getLength() {
		return length;
	}

	//between 20 and 60 bytes
	public int getHeaderLength() {
		// TODO Auto-generated method stub
		return 0;
	}

	//length - ip_header - tcp_header
	public int getDataLength() {
		return 0;
	}

	public long getSequence() {
		return sequence;
	}

	@Override
	public long getAckNum() {
		return 0;
	}

	//has no data
	public byte[] getData() {
		return null;
	}

	@Override
	public boolean getSyn() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean getAck() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean getFin() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean getPsh() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public long getTimestampSec() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public long getTimestampUSec() {
		// TODO Auto-generated method stub
		return 0;
	}

}
