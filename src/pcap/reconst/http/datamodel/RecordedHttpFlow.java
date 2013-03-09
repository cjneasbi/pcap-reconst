package pcap.reconst.http.datamodel;

import org.apache.http.HttpRequest;


public class RecordedHttpFlow {

	private byte[] rawdata;
	private HttpRequest request;
	private RecordedHttpResponse response;
	
	public RecordedHttpFlow(byte[] rawdata, HttpRequest request, 
			RecordedHttpResponse response) {
		this.rawdata = rawdata;
		this.request = request;
		this.response = response;
	}

	public byte[] getRawdata() {
		return rawdata;
	}

	public HttpRequest getRequest() {
		return request;
	}

	public RecordedHttpResponse getResponse() {
		return response;
	}

}
