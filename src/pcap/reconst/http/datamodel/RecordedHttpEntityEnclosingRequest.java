package pcap.reconst.http.datamodel;

import java.net.InetAddress;

import org.apache.http.ProtocolVersion;
import org.apache.http.RequestLine;
import org.apache.http.message.BasicHttpEntityEnclosingRequest;

import pcap.reconst.tcp.MessageMetadata;
import pcap.reconst.tcp.TcpConnection;
import pcap.reconst.tcp.TimestampPair;

public class RecordedHttpEntityEnclosingRequest extends
		BasicHttpEntityEnclosingRequest implements RecordedHttpMessage {

	protected MessageMetadata messdata;
	
	public RecordedHttpEntityEnclosingRequest(RequestLine requestline, 
			MessageMetadata messdata) {
		super(requestline);
		this.messdata = messdata;
	}

	public RecordedHttpEntityEnclosingRequest(String method, String uri, 
			MessageMetadata messdata) {
		super(method, uri);
		this.messdata = messdata;
	}

	public RecordedHttpEntityEnclosingRequest(String method, String uri,
			ProtocolVersion ver, MessageMetadata messdata) {
		super(method, uri, ver);
		this.messdata = messdata;
	}

	@Override
	public TimestampPair getTimestamps() {
		return this.messdata.getTimestamps();
	}

	@Override
	public double getStartTS() {
		return this.messdata.getTimestamps().getStartTS();
	}

	@Override
	public double getEndTS() {
		return this.messdata.getTimestamps().getEndTS();
	}

	@Override
	public TcpConnection getTcpConnection() {
		return this.messdata.getTcpConnection();
	}

	@Override
	public InetAddress getSrcIp() {
		return this.messdata.getSrcIp();
	}

	@Override
	public InetAddress getDstIp() {
		return this.messdata.getDstIp();
	}

	@Override
	public int getSrcPort() {
		return this.messdata.getSrcPort();
	}

	@Override
	public int getDstPort() {
		return this.messdata.getDstPort();
	}

}
