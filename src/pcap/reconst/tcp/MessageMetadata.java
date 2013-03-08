package pcap.reconst.tcp;

import java.net.InetAddress;


public class MessageMetadata {

	private TimestampPair ts;
	private TcpConnection conn;

	public MessageMetadata(TimestampPair ts, TcpConnection conn) {
		this.ts = ts;
		this.conn = conn;
	}

	public TimestampPair getTimestamps() {
		return this.ts;
	}

	public double getStartTS() {
		return this.ts.getStartTS();
	}

	public double getEndTS() {
		return this.ts.getEndTS();
	}

	public TcpConnection getTcpConnection() {
		return this.conn;
	}

	public InetAddress getSrcIp() {
		return this.conn.getSrcIp();
	}

	public InetAddress getDstIp() {
		return this.conn.getDstIp();
	}

	public int getSrcPort() {
		return this.conn.getSrcPort();
	}

	public int getDstPort() {
		return this.conn.getDstPort();
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof MessageMetadata) {
			MessageMetadata objm = (MessageMetadata) obj;
			return this.conn.equals(objm.conn) && this.ts.equals(objm.ts);
		}
		return false;
	}

}
