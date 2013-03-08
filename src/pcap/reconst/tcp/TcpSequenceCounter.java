/*
 * Author: Chris Neasbitt
 */

package pcap.reconst.tcp;

import java.net.InetAddress;

public class TcpSequenceCounter {
	private InetAddress address;
	private long port;
	private long seq;

	public TcpSequenceCounter(InetAddress address, long port) {
		this.address = address;
		this.port = port;
	}

	public InetAddress getAddress() {
		return address;
	}

	public long getPort() {
		return port;
	}

	public void setSeq(long seq) {
		this.seq = seq;
	}

	public void incrementSeq() {
		seq++;
	}

	public long getSeq() {
		return seq;
	}

	public void addToSeq(long length) {
		seq += length;
	}

	public String getOutputName() {
		return address.toString().replace("/", "") + "_" + port;
	}

	@Override
	public String toString() {
		return this.getOutputName() + " seq: " + this.seq;
	}
}
