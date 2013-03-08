package pcap.reconst.beans;

import java.net.InetAddress;

import pcap.reconst.tcp.MessageMetadata;
import pcap.reconst.tcp.TcpConnection;
import pcap.reconst.tcp.TimestampPair;

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
	
	public int getStatus(){
		return (int)this.getStatusFloat();
	}
	
	public float getStatusFloat(){
		String[] parts = new String(this.data).split("\r\n", 2)[0].split("\\s");
		return Float.parseFloat(parts[1]);
	}

}
