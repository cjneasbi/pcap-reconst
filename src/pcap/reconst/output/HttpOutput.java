/*
 * Author: Manoj Bharadwaj
 */

package pcap.reconst.output;

import pcap.reconst.beans.HTTPRequest;
import pcap.reconst.beans.HTTPResponse;

public class HttpOutput {
	private byte[] payload;
	private HTTPRequest request;
	private HTTPResponse response;

	public HttpOutput(byte[] payload, HTTPRequest request, HTTPResponse response) {
		this.payload = payload;
		this.request = request;
		this.response = response;
	}

	public byte[] getPayload() {
		return payload;
	}

	public HTTPRequest getRequest() {
		return request;
	}

	public HTTPResponse getResponse() {
		return response;
	}
}
