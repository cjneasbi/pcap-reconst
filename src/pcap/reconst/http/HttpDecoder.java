/*
 * Author(s): Manoj Bharadwaj, Chris Neasbitt
 */

package pcap.reconst.http;

import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpResponse;

import pcap.reconst.decoder.Decoder;
import pcap.reconst.decoder.DecoderFactory;
import pcap.reconst.http.datamodel.RecordedHttpFlow;
import pcap.reconst.tcp.TcpConnection;

public class HttpDecoder {
	private static Log log = LogFactory.getLog(HttpDecoder.class);

	public static void decodeResponses(Map<TcpConnection, List<RecordedHttpFlow>> httpFlows){
		for (TcpConnection tcpConnection : httpFlows.keySet()) {
			List<RecordedHttpFlow> flowList = httpFlows.get(tcpConnection);
			for (RecordedHttpFlow flow : flowList) {
				if(flow.getResponse() != null){
					try{
						HttpEntity decodedEnt = decodeResponse(flow.getResponse());
						if(decodedEnt != null){
							flow.getResponse().setEntity(decodedEnt);
						}
					} catch (Exception e) {
						if(log.isErrorEnabled()){
							log.error("Error decoding response.", e);
						}
					}
				}
			}
		}
	}
	
	public static HttpEntity decodeRequest(HttpEntityEnclosingRequest req) throws Exception{
		Decoder decoder = DecoderFactory.getDecoder();
		if(req.getEntity() != null){
			return decoder.decodeEntity(req.getEntity());
		}
		return null;
	}
	
	public static HttpEntity decodeResponse(HttpResponse resp) throws Exception{
		Decoder decoder = DecoderFactory.getDecoder();
		if(resp.getEntity() != null){
			return decoder.decodeEntity(resp.getEntity());
		}
		return null;
	}
}
