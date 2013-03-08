/*
 * Author: Chris Neasbitt
 */

package pcap.reconst.tcp;

public class TimestampPair {

	private double startTS, endTS;

	public TimestampPair(double startTS, double endTS) {
		this.startTS = startTS;
		this.endTS = endTS;
	}

	public double getStartTS() {
		return this.startTS;
	}

	public double getEndTS() {
		return this.endTS;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof TimestampPair) {
			TimestampPair objp = (TimestampPair) obj;
			return this.startTS == objp.startTS && this.endTS == objp.endTS;
		}
		return false;
	}

	@Override
	public String toString() {
		return "start: " + this.startTS + " end: " + this.endTS;
	}

}
