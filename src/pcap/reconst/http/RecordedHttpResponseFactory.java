package pcap.reconst.http;

import org.apache.http.HttpResponse;
import org.apache.http.ProtocolVersion;
import org.apache.http.ReasonPhraseCatalog;
import org.apache.http.StatusLine;
import org.apache.http.impl.DefaultHttpResponseFactory;
import org.apache.http.protocol.HttpContext;

import pcap.reconst.http.datamodel.RecordedHttpResponse;
import pcap.reconst.tcp.MessageMetadata;

public class RecordedHttpResponseFactory extends DefaultHttpResponseFactory {

	protected MessageMetadata messdata;
	
	public RecordedHttpResponseFactory(MessageMetadata messdata) {
		this.messdata = messdata;
	}

	public RecordedHttpResponseFactory(ReasonPhraseCatalog catalog, 
			MessageMetadata messdata) {
		super(catalog);
		this.messdata = messdata;
	}
	
	public HttpResponse newHttpResponse(final ProtocolVersion ver,
            final int status,
            HttpContext context) {
		HttpResponse resp = super.newHttpResponse(ver, status, context);
		return new RecordedHttpResponse(resp.getStatusLine(), reasonCatalog, 
				resp.getLocale(), messdata);	
	}
	
    public HttpResponse newHttpResponse(final StatusLine statusline,
            HttpContext context) {
    	HttpResponse resp = super.newHttpResponse(statusline, context);
		return new RecordedHttpResponse(resp.getStatusLine(), reasonCatalog, 
				resp.getLocale(), messdata);
    }

}
