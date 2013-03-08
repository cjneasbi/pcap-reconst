package pcap.reconst.http.datamodel;

import java.net.InetAddress;

import org.apache.http.HttpMessage;

import pcap.reconst.tcp.TcpConnection;
import pcap.reconst.tcp.TimestampPair;

public interface RecordedHttpMessage extends HttpMessage {

	public TimestampPair getTimestamps();
	public double getStartTS();
	public double getEndTS();
	public TcpConnection getTcpConnection();
	public InetAddress getSrcIp();
	public InetAddress getDstIp();
	public int getSrcPort();
	public int getDstPort();
}
