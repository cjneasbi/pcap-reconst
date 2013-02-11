package pcap.reconst.beans;

import org.apache.commons.lang3.StringUtils;

public class HTTPMessage extends InputData {

	public HTTPMessage(byte[] data, TimestampPair ts){
		super(data, null, ts);
		this.setHeaders(getHeaders(new String(data)));
	}
	
	private Headers getHeaders(String stringWithHeaders) {
		Headers headers = new Headers();
		String[] tokens = stringWithHeaders.split("\r\n");
		for (String token : tokens) {
			if (StringUtils.isEmpty(token)) {
				break;
			}
			if (token.contains(": ")) {
				String[] values = token.split(": ");
				if (values.length > 1) {
					headers.addHeader(values[0], values[1]);
				} else {
					headers.addHeader(values[0], null);
				}
			}
		}
		return headers;
	}
}
