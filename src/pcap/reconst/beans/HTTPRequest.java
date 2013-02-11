package pcap.reconst.beans;

public class HTTPRequest extends HTTPMessage {
	
	public HTTPRequest(byte[] data, TimestampPair ts){
		super(data, ts);
	}
	
	public String getPath(){
		String[] parts = new String(this.data).split("\r\n", 2)[0]
				.split("\\s");
		return parts[1];
	}
	
	public String getMethod(){
		String[] parts = new String(this.data).split("\r\n", 2)[0]
				.split("\\s");
		return parts[0];
	}
}
