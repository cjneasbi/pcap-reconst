package pcap.reconst.http.datamodel;

import java.net.InetAddress;
import java.util.Locale;

import org.apache.http.ProtocolVersion;
import org.apache.http.ReasonPhraseCatalog;
import org.apache.http.StatusLine;
import org.apache.http.message.BasicHttpResponse;

import pcap.reconst.tcp.MessageMetadata;

public class RecordedHttpResponse extends BasicHttpResponse implements
		RecordedHttpMessage {

	protected MessageMetadata messdata;
	
	public RecordedHttpResponse(StatusLine statusline, 
			MessageMetadata messdata) {
		super(statusline);
		this.messdata = messdata;
	}

	public RecordedHttpResponse(StatusLine statusline,
			ReasonPhraseCatalog catalog, Locale locale, 
			MessageMetadata messdata) {
		super(statusline, catalog, locale);
		this.messdata = messdata;
	}

	public RecordedHttpResponse(ProtocolVersion ver, int code, String reason, 
			MessageMetadata messdata) {
		super(ver, code, reason);
		this.messdata = messdata;
	}

	@Override
	public double getStartTS() {
		return this.messdata.getTimestamps().getStartTS();
	}

	@Override
	public double getEndTS() {
		return this.messdata.getTimestamps().getEndTS();
	}

	@Override
	public InetAddress getSrcIp() {
		return this.messdata.getSrcIp();
	}

	@Override
	public InetAddress getDstIp() {
		return this.messdata.getDstIp();
	}

	@Override
	public int getSrcPort() {
		return this.messdata.getSrcPort();
	}

	@Override
	public int getDstPort() {
		return this.messdata.getDstPort();
	}
	
	@Override
	public boolean equals(Object obj){
		if(obj instanceof RecordedHttpResponse){
			RecordedHttpResponse mess = (RecordedHttpResponse)obj;
			return mess.getDstIp().equals(this.getDstIp()) &&
					mess.getDstPort() == this.getDstPort() &&
					mess.getSrcIp().equals(this.getSrcIp()) &&
					mess.getSrcPort() == this.getSrcPort() &&
					mess.getStartTS() == this.getStartTS() &&
					mess.getEndTS() == this.getEndTS() &&
					mess.getLocale().equals(this.getLocale()) &&
					Utils.equals(mess.getAllHeaders(), this.getAllHeaders()) &&
					Utils.equals(mess.getStatusLine(), this.getStatusLine()) &&
					Utils.equals(mess.getEntity(), this.getEntity());			
		}
		return false;
	}

}
