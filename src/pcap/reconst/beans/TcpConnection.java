/*
 * Author: Manoj Bharadwaj
 */

package pcap.reconst.beans;

import pcap.reconst.beans.packet.TcpPacket;
import pcap.reconst.beans.packet.TestTcpPacket;

import java.net.InetAddress;

public class TcpConnection implements Comparable<TcpConnection> {
    private InetAddress srcIp;
    private int srcPort;
    private InetAddress dstIp;
    private int dstPort;

    public TcpConnection(InetAddress sourceIP, int sourcePort, 
    		InetAddress destinationIP, int destinationPort) {
        this(new TestTcpPacket(sourceIP, sourcePort, destinationIP, destinationPort));
    }

    public TcpConnection(TcpPacket packet) {
        srcIp = packet.getSourceIP();
        dstIp = packet.getDestinationIP();
        srcPort = packet.getSourcePort();
        dstPort = packet.getDestinationPort();
    }

    public InetAddress getSrcIp() {
        return srcIp;
    }

    public int getSrcPort() {
        return srcPort;
    }

    public InetAddress getDstIp() {
        return dstIp;
    }

    public int getDstPort() {
        return dstPort;
    }

    //ensures both request and response are reconstructed together
    public boolean equals(Object obj) {
        if (!(obj instanceof TcpConnection))
            return false;

        TcpConnection con = (TcpConnection) obj;

        return ((con.srcIp.equals(srcIp)) && (con.srcPort == srcPort) && (con.dstIp.equals(dstIp)) && (con.dstPort == dstPort)) ||
                ((con.srcIp.equals(dstIp)) && (con.srcPort == dstPort) && (con.dstIp.equals(srcIp)) && (con.dstPort == srcPort));

    }

    public TcpConnection() {
    }

    public int hashCode() {
        return ((srcIp.hashCode() ^ srcPort) ^
                ((dstIp.hashCode() ^ dstPort)));
    }

    @Override
    public String toString() {
    	return srcIp.toString().replace("/", "") + "." + srcPort + 
    			"-" + dstIp.toString().replace("/", "") + "." + dstPort;
    }

/*
    public String getFileName(String path) {
        return String.format("%s%s.data", path, toString());
    }

*/

	@Override
	public int compareTo(TcpConnection other) {
        if (this.equals(other)) {
            return 0;
        }

        if (getSrcPort() != 80 && other.getSrcPort() != 80) {
            return getSrcPort() - other.getSrcPort();
        } else if (getDstPort() != 80 && other.getDstPort() != 80) {
            return getDstPort() - other.getDstPort();
        } else {
            return getDstPort() * 2 + getSrcPort() - other.getSrcPort() * 2 + other.getDstPort();
        }
	}
}
