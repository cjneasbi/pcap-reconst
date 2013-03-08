/*
 * Author(s): Manoj Bharadwaj, Chris Neasbitt
 */

package pcap.reconst.tcp.packet;

import java.net.InetAddress;

public class TestTcpPacket implements TcpPacket {
	private InetAddress sourceIP;
	private int sourcePort;
	private InetAddress destinationIP;
	private int destinationPort;

	public TestTcpPacket(InetAddress sourceIP, int sourcePort,
			InetAddress destinationIP, int destinationPort) {
		this.sourceIP = sourceIP;
		this.sourcePort = sourcePort;
		this.destinationIP = destinationIP;
		this.destinationPort = destinationPort;
	}

	@Override
	public InetAddress getSourceIP() {
		return sourceIP;
	}

	@Override
	public int getSourcePort() {
		return sourcePort;
	}

	@Override
	public InetAddress getDestinationIP() {
		return destinationIP;
	}

	@Override
	public int getDestinationPort() {
		return destinationPort;
	}

	@Override
	public int getCaptureLength() {
		return 0;
	}

	@Override
	public int getLength() {
		return 0;
	}

	@Override
	public int getHeaderLength() {
		return 0;
	}

	@Override
	public int getDataLength() {
		return 0;
	}

	@Override
	public long getSequence() {
		return 0;
	}

	@Override
	public long getAckNum() {
		return 0;
	}

	@Override
	public byte[] getData() {
		return new byte[0];
	}

	@Override
	public boolean getSyn() {
		return false;
	}

	@Override
	public boolean getAck() {
		return false;
	}

	@Override
	public boolean getFin() {
		return false;
	}

	@Override
	public boolean getPsh() {
		return false;
	}

	@Override
	public long getTimestampSec() {
		return 0;
	}

	@Override
	public long getTimestampUSec() {
		return 0;
	}
}
