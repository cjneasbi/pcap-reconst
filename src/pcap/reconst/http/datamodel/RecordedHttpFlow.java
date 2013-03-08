package pcap.reconst.http.datamodel;


public class RecordedHttpFlow {

	private byte[] rawdata;
	private RecordedHttpRequest request;
	private RecordedHttpResponse response;
	
	public RecordedHttpFlow(byte[] rawdata, RecordedHttpRequest request, 
			RecordedHttpResponse response) {
		this.rawdata = rawdata;
		this.request = request;
		this.response = response;
	}

	public byte[] getRawdata() {
		return rawdata;
	}

	public RecordedHttpRequest getRequest() {
		return request;
	}

	public RecordedHttpResponse getResponse() {
		return response;
	}

}
