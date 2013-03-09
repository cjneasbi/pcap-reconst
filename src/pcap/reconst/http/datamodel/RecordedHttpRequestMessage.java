package pcap.reconst.http.datamodel;

import org.apache.http.HttpRequest;

public interface RecordedHttpRequestMessage extends 
	RecordedHttpMessage, HttpRequest {

	public String getUrl();
}
