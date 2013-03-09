package pcap.reconst.http.datamodel;

import org.apache.http.HttpMessage;

import pcap.reconst.tcp.TimestampPair;

public interface TimestampedHttpMessage extends HttpMessage {

	public TimestampPair getTimestamps();
	public double getStartTS();
	public double getEndTS();
}
