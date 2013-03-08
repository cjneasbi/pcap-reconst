package pcap.reconst.http;

import java.io.IOException;

import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.impl.entity.EntityDeserializer;
import org.apache.http.impl.entity.LaxContentLengthStrategy;
import org.apache.http.impl.io.DefaultHttpRequestParser;
import org.apache.http.impl.io.DefaultHttpResponseParser;
import org.apache.http.io.SessionInputBuffer;
import org.apache.http.message.BasicLineParser;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.CoreProtocolPNames;
import org.apache.http.params.HttpParams;

import pcap.reconst.http.datamodel.MessageStringInputBuffer;
import pcap.reconst.tcp.MessageMetadata;

public class RecordedHttpMessageParser {

	public static HttpRequest parseRecordedRequest(String reqstring, MessageMetadata messdata) throws IOException, HttpException{
		MessageStringInputBuffer buf = new MessageStringInputBuffer(reqstring);
		DefaultHttpRequestParser parser = new DefaultHttpRequestParser(buf, 
				new BasicLineParser(), 
				new RecordedHttpRequestFactory(messdata), 
				new BasicHttpParams());
		HttpRequest request = parser.parse();
		if(request instanceof HttpEntityEnclosingRequest){
			parseEntity((HttpEntityEnclosingRequest)request, buf);
		}
		return request;
	}
	
	public static HttpResponse parseRecordedResponse(String respstring, MessageMetadata messdata) throws IOException, HttpException {
		MessageStringInputBuffer buf = new MessageStringInputBuffer(respstring);
		DefaultHttpResponseParser parser = new DefaultHttpResponseParser(buf, 
				new BasicLineParser(), 
				new RecordedHttpResponseFactory(messdata), 
				new BasicHttpParams());
		HttpResponse response = parser.parse();
		parseEntity(response, buf);
		return response;
	}
	
	private static void parseEntity(HttpEntityEnclosingRequest request, SessionInputBuffer buf) throws IOException, HttpException{
		if(request.getParams().isParameterTrue(CoreProtocolPNames.STRICT_TRANSFER_ENCODING)){
			HttpParams params = request.getParams();
			params.setBooleanParameter(CoreProtocolPNames.STRICT_TRANSFER_ENCODING, false);
		}
		EntityDeserializer deserial = new EntityDeserializer(new LaxContentLengthStrategy());
		request.setEntity(deserial.deserialize(buf, request));
	}
	
	private static void parseEntity(HttpResponse response, SessionInputBuffer buf) throws IOException, HttpException{
		if(response.getParams().isParameterTrue(CoreProtocolPNames.STRICT_TRANSFER_ENCODING)){
			HttpParams params = response.getParams();
			params.setBooleanParameter(CoreProtocolPNames.STRICT_TRANSFER_ENCODING, false);
		}
		EntityDeserializer deserial = new EntityDeserializer(new LaxContentLengthStrategy());
		response.setEntity(deserial.deserialize(buf, response));
	}
}
