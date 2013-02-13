package pcap.reconst.beans;

import java.net.InetAddress;

import org.apache.commons.lang3.StringUtils;

public class HTTPMessage extends InputData {

	protected TcpConnection conn;

	public HTTPMessage(byte[] data, TimestampPair ts, InetAddress src,
			int srcport, InetAddress dst, int dstport) {
		super(data, null, ts);
		this.setHeaders(parseHeaders(new String(data)));
		this.conn = new TcpConnection(src, srcport, dst, dstport);
	}

	public HTTPMessage(byte[] data, MessageMetadata mdata) {
		this(data, mdata.getTimestamps(), mdata.getTcpConnection());
	}

	public HTTPMessage(byte[] data, TimestampPair ts, TcpConnection conn) {
		super(data, null, ts);
		this.setHeaders(parseHeaders(new String(data)));
		this.conn = conn;
	}

	private Headers parseHeaders(String stringWithHeaders) {
		Headers headers = new Headers();
		String[] tokens = stringWithHeaders.split("\r\n");
		for (String token : tokens) {
			if (StringUtils.isEmpty(token)) {
				break;
			}
			if (token.contains(": ")) {
				String[] values = token.split(": ");
				if (values.length > 1) {
					headers.addHeader(values[0], values[1]);
				} else {
					headers.addHeader(values[0], null);
				}
			}
		}
		return headers;
	}

	public TcpConnection getTcpConnection() {
		return this.conn;
	}

	protected void setTcpConnection(TcpConnection conn) {
		this.conn = conn;
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
		if (obj instanceof HTTPMessage) {
			HTTPMessage objm = (HTTPMessage) obj;
			return super.equals(objm) && this.conn.equals(objm.conn);
		}
		return false;
	}
}
