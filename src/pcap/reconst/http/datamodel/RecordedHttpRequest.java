package pcap.reconst.http.datamodel;

import java.net.InetAddress;

import org.apache.http.ProtocolVersion;
import org.apache.http.RequestLine;
import org.apache.http.message.BasicHttpRequest;

import pcap.reconst.tcp.MessageMetadata;

public class RecordedHttpRequest extends BasicHttpRequest implements
		RecordedHttpRequestMessage {

	protected MessageMetadata messdata;
	
	public RecordedHttpRequest(RequestLine requestline,
			MessageMetadata messdata) {
		super(requestline);
		this.messdata = messdata;
	}

	public RecordedHttpRequest(String method, String uri, 
			MessageMetadata messdata) {
		super(method, uri);
		this.messdata = messdata;
	}

	public RecordedHttpRequest(String method, String uri, 
			ProtocolVersion ver, MessageMetadata messdata) {
		super(method, uri, ver);
		this.messdata = messdata;
	}
	
	public String getUrl(){
		String host = this.getFirstHeader("Host").getValue();
		String retval = "http://";
		if (host != null) {
			retval += host;
		} else {
			retval += messdata.getDstIp().toString().replace("/", "");
		}
		if (messdata.getDstPort() != 80) {
			retval = retval + ":" + messdata.getDstPort();
		}
		return retval + this.getRequestLine().getUri();
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
	
	@Override
	public boolean equals(Object obj){
		if(obj instanceof RecordedHttpRequest){
			RecordedHttpRequest mess = (RecordedHttpRequest)obj;
			return mess.getDstIp().equals(this.getDstIp()) &&
					mess.getDstPort() == this.getDstPort() &&
					mess.getSrcIp().equals(this.getSrcIp()) &&
					mess.getSrcPort() == this.getSrcPort() &&
					mess.getStartTS() == this.getStartTS() &&
					mess.getEndTS() == this.getEndTS() &&
					Utils.equals(mess.getAllHeaders(), this.getAllHeaders()) &&
					Utils.equals(mess.getRequestLine(), this.getRequestLine());		
		}
		return false;
	}

}
