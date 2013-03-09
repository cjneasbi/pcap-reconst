package pcap.reconst.http.datamodel;

import java.net.InetAddress;

public interface RecordedHttpMessage extends TimestampedHttpMessage {

	public InetAddress getSrcIp();
	public InetAddress getDstIp();
	public int getSrcPort();
	public int getDstPort();
}
