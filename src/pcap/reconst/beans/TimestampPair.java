/*
 * Author: Chris Neasbitt
 */

package pcap.reconst.beans;

public class TimestampPair {

	private double startTS, endTS;
	
	public TimestampPair(double startTS, double endTS){
		this.startTS = startTS;
		this.endTS = endTS;
	}
	
	public double getStartTS(){
		return this.startTS;
	}
	
	public double getEndTS(){
		return this.endTS;
	}
	
	public String toString(){
		return "start: " + this.startTS + " end: " + this.endTS;
	}
	
}
