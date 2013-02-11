/*
 * Author(s): Manoj Bharadwaj, Chris Neasbitt
 */

package pcap.reconst.beans;

import pcap.reconst.Utils;

public class InputData {
	protected byte[] data;
	protected Headers headers;
	protected TimestampPair ts;

	public InputData(byte[] data, Headers headers, TimestampPair ts) {
		this.data = data;
		this.headers = headers;
		this.ts = ts;
	}

	public TimestampPair getTimestamps() {
		return ts;
	}
	
	protected void setData(byte[] data){
		this.data = data;
	}

	protected void setTimestamps(TimestampPair ts){
		this.ts = ts;
	}
	
	protected void setHeaders(Headers headers){
		this.headers = headers;
	}
	
	public Headers getHeaders() {
		return headers;
	}

	public byte[] getData() {
		return data;
	}

	public int getInputLength() {
		return data.length;
	}

	public int getContentLength() {
		return headers.getContentLength();
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		if (headers != null) {
			builder.append("Headers...\n");
			for (String name : headers.getNames()) {
				builder.append(name + ": " + headers.getValue(name) + "\n");
			}
		}
		builder.append("Encoded string: " + new String(data) + "\n");
		return builder.toString();
	}

	public void printHex() {
		Utils.prettyPrintHex(data);
	}
}