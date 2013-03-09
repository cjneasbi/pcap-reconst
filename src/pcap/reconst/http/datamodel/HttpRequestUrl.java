package pcap.reconst.http.datamodel;

import org.apache.http.HttpRequest;

public interface HttpRequestUrl extends HttpRequest {
	public String getUrl();
}
