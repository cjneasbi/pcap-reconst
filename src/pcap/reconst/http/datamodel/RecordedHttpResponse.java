package pcap.reconst.http.datamodel;

import java.net.InetAddress;
import java.util.Locale;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.ProtocolVersion;
import org.apache.http.ReasonPhraseCatalog;
import org.apache.http.StatusLine;
import org.apache.http.message.BasicHttpResponse;

import pcap.reconst.tcp.MessageMetadata;

public class RecordedHttpResponse extends BasicHttpResponse implements
		RecordedHttpMessage {

	protected MessageMetadata messdata;
	
	private static Log log = LogFactory.getLog(RecordedHttpResponse.class);
	
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
		boolean retval = false;
		if(obj instanceof RecordedHttpResponse){
			RecordedHttpResponse mess = (RecordedHttpResponse)obj;
			try{
				retval = mess.getDstIp().equals(this.getDstIp()) &&
						mess.getDstPort() == this.getDstPort() &&
						mess.getSrcIp().equals(this.getSrcIp()) &&
						mess.getSrcPort() == this.getSrcPort() &&
						mess.getStartTS() == this.getStartTS() &&
						mess.getEndTS() == this.getEndTS() &&
						mess.getLocale().equals(this.getLocale()) &&
						Utils.equals(mess.getAllHeaders(), this.getAllHeaders()) &&
						Utils.equals(mess.getStatusLine(), this.getStatusLine()) &&
						mess.getEntity().getContent() == this.getEntity().getContent();
				
				if(log.isDebugEnabled() && !retval){
					log.debug("Not equals dstip: " + mess.getDstIp().equals(this.getDstIp()) +
					" dstport: " + (mess.getDstPort() == this.getDstPort()) +
					" srcip: " + mess.getSrcIp().equals(this.getSrcIp()) +
					" srcport: " + (mess.getSrcPort() == this.getSrcPort()) +
					" startts: " + (mess.getStartTS() == this.getStartTS()) +
					" endts: " + (mess.getEndTS() == this.getEndTS()) +
					" locale: " + mess.getLocale().equals(this.getLocale()) +
					" headers: " + Utils.equals(mess.getAllHeaders(), this.getAllHeaders()) +
					" statusline: " + Utils.equals(mess.getStatusLine(), this.getStatusLine()) +
					" entity: " + (mess.getEntity().getContent() == this.getEntity().getContent()));
				}
			} catch (Exception e){
				if(log.isDebugEnabled()){
					log.debug("Error retrieving content.", e);
				}
			}
		}
		return retval;
	}

}
