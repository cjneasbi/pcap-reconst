package pcap.reconst.http.datamodel;

public class RecordedHttpFlow {

	private byte[] rawdata;
	private RecordedHttpRequestMessage request;
	private RecordedHttpResponse response;
	
	public RecordedHttpFlow(byte[] rawdata, RecordedHttpRequestMessage request, 
			RecordedHttpResponse response) {
		this.rawdata = rawdata;
		this.request = request;
		this.response = response;
	}

	public byte[] getRawdata() {
		return rawdata;
	}

	public RecordedHttpRequestMessage getRequest() {
		return request;
	}

	public RecordedHttpResponse getResponse() {
		return response;
	}

}
