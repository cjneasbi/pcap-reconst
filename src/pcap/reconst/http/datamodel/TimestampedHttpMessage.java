package pcap.reconst.http.datamodel;

import org.apache.http.HttpMessage;

public interface TimestampedHttpMessage extends HttpMessage {

	public double getStartTS();
	public double getEndTS();
}
