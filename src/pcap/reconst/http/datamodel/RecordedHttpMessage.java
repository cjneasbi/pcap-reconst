package pcap.reconst.http.datamodel;

import java.net.InetAddress;

import pcap.reconst.tcp.TcpConnection;

public interface RecordedHttpMessage extends TimestampedHttpMessage {

	public TcpConnection getTcpConnection();
	public InetAddress getSrcIp();
	public InetAddress getDstIp();
	public int getSrcPort();
	public int getDstPort();
}
