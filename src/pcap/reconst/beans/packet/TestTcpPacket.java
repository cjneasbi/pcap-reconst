/*
 * Author(s): Manoj Bharadwaj, Chris Neasbitt
 */

package pcap.reconst.beans.packet;

import java.net.InetAddress;

public class TestTcpPacket implements TcpPacket {
    private InetAddress sourceIP;
    private int sourcePort;
    private InetAddress destinationIP;
    private int destinationPort;

    public TestTcpPacket(InetAddress sourceIP, int sourcePort, InetAddress destinationIP, int destinationPort) {
        this.sourceIP = sourceIP;
        this.sourcePort = sourcePort;
        this.destinationIP = destinationIP;
        this.destinationPort = destinationPort;
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

    public int getCaptureLength() {
        return 0;
    }

    public int getLength() {
        return 0;
    }

    public int getHeaderLength() {
        return 0;
    }

    public int getDataLength() {
        return 0;
    }

    public long getSequence() {
        return 0;
    }

    public long getAckNum() {
        return 0;
    }

    public byte[] getData() {
        return new byte[0];
    }

    public boolean getSyn() {
        return false;
    }

	public boolean getAck() {
		return false;
	}

	public boolean getFin() {
		return false;
	}

	public boolean getPsh() {
		return false;
	}

	public long getTimestampSec() {
		return 0;
	}

	public long getTimestampUSec() {
		return 0;
	}
}
