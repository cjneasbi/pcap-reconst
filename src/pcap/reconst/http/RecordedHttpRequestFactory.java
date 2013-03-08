package pcap.reconst.http;

import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestFactory;
import org.apache.http.MethodNotSupportedException;
import org.apache.http.RequestLine;

import pcap.reconst.http.datamodel.RecordedHttpEntityEnclosingRequest;
import pcap.reconst.http.datamodel.RecordedHttpRequest;
import pcap.reconst.tcp.MessageMetadata;

public class RecordedHttpRequestFactory implements HttpRequestFactory {

	protected MessageMetadata messdata;
		
	public RecordedHttpRequestFactory(MessageMetadata messdata) {
		this.messdata = messdata;
	}
	
	private static final String[] RFC2616_COMMON_METHODS = {
        "GET"
    };

    private static final String[] RFC2616_ENTITY_ENC_METHODS = {
        "POST",
        "PUT"
    };

    private static final String[] RFC2616_SPECIAL_METHODS = {
        "HEAD",
        "OPTIONS",
        "DELETE",
        "TRACE",
        "CONNECT"
    };

    private static boolean isOneOf(final String[] methods, final String method) {
        for (int i = 0; i < methods.length; i++) {
            if (methods[i].equalsIgnoreCase(method)) {
                return true;
            }
        }
        return false;
    }

    public HttpRequest newHttpRequest(final RequestLine requestline)
            throws MethodNotSupportedException {
        if (requestline == null) {
            throw new IllegalArgumentException("Request line may not be null");
        }
        String method = requestline.getMethod();
        if (isOneOf(RFC2616_COMMON_METHODS, method)) {
            return new RecordedHttpRequest(requestline, messdata);
        } else if (isOneOf(RFC2616_ENTITY_ENC_METHODS, method)) {
            return new RecordedHttpEntityEnclosingRequest(requestline, messdata);
        } else if (isOneOf(RFC2616_SPECIAL_METHODS, method)) {
            return new RecordedHttpRequest(requestline, messdata);
        } else {
            throw new MethodNotSupportedException(method +  " method not supported");
        }
    }

    public HttpRequest newHttpRequest(final String method, final String uri)
            throws MethodNotSupportedException {
        if (isOneOf(RFC2616_COMMON_METHODS, method)) {
            return new RecordedHttpRequest(method, uri, messdata);
        } else if (isOneOf(RFC2616_ENTITY_ENC_METHODS, method)) {
            return new RecordedHttpEntityEnclosingRequest(method, uri, messdata);
        } else if (isOneOf(RFC2616_SPECIAL_METHODS, method)) {
            return new RecordedHttpRequest(method, uri, messdata);
        } else {
            throw new MethodNotSupportedException(method
                    + " method not supported");
        }
    }
}
