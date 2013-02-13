package pcap.reconst.beans;

import java.net.InetAddress;

public class HTTPResponse extends HTTPMessage {

	public HTTPResponse(byte[] data, TimestampPair ts, InetAddress src,
			int srcport, InetAddress dst, int dstport) {
		super(data, ts, src, srcport, dst, dstport);
	}

	public HTTPResponse(byte[] data, MessageMetadata mdata) {
		super(data, mdata);
	}

	public HTTPResponse(byte[] data, TimestampPair ts, TcpConnection conn) {
		super(data, ts, conn);
	}

}
