package pcap.reconst.http.datamodel;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


public class RecordedHttpFlow {

	private byte[] rawdata;
	private RecordedHttpRequestMessage request;
	private RecordedHttpResponse response;
	
	private static Log log = LogFactory.getLog(RecordedHttpFlow.class);
	
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
	
	@Override
	public boolean equals(Object obj){
		boolean retval = false;
		if(obj instanceof RecordedHttpFlow){
			RecordedHttpFlow flow = (RecordedHttpFlow)obj;
			retval = flow.rawdata.equals(this.rawdata) && 
					flow.request.equals(this.request);
			
			//the response can be optionally null
			if(retval){
				if(flow.response != null && this.response != null){
					retval = flow.response.equals(this.response);
				} else if(flow.response == null && this.response == null){
					retval = true;
				}
			}
			if(log.isDebugEnabled() && !retval){
				String val = "Not equals raw: " + flow.rawdata.equals(this.rawdata) + 
						" request: " + flow.request.equals(this.request);
				if(flow.response != null && this.response != null){
					val += " response: " + flow.response.equals(this.response);
				}
				log.debug(val);
			}
		}
		return retval;
	}

}
