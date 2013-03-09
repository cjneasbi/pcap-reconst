/*
 * Author: Chris Neasbitt
 */

package pcap.reconst.example;

import java.io.File;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpRequest;
import org.apache.http.util.EntityUtils;

import pcap.reconst.http.HttpDecoder;
import pcap.reconst.http.HttpFlowParser;
import pcap.reconst.http.datamodel.RecordedHttpEntityEnclosingRequest;
import pcap.reconst.http.datamodel.RecordedHttpFlow;
import pcap.reconst.http.datamodel.RecordedHttpRequest;
import pcap.reconst.http.datamodel.RecordedHttpResponse;
import pcap.reconst.tcp.JpcapReconstructor;
import pcap.reconst.tcp.PacketReassembler;
import pcap.reconst.tcp.Reconstructor;
import pcap.reconst.tcp.TcpConnection;
import pcap.reconst.tcp.TcpReassembler;

public class HttpReconstructorExample {

	private static Log log = LogFactory.getLog(HttpReconstructorExample.class);

	public Map<TcpConnection, TcpReassembler> reconstruct(File inputFile,
			Reconstructor reconstructor) throws Exception {
		return reconstructor.reconstruct(inputFile.getAbsolutePath());
	}

	public static void main(String[] args) {
		try {
			HttpReconstructorExample fileDataReconstructor = new HttpReconstructorExample();
			
			//Reassemble the TCP streams.
			Map<TcpConnection, TcpReassembler> map = fileDataReconstructor
					.reconstruct(new File(args[0]), new JpcapReconstructor(
							new PacketReassembler()));
			
			//Parse the HTTP flows from the streams.
			HttpFlowParser httpParser = new HttpFlowParser(map);
			Map<TcpConnection, List<RecordedHttpFlow>> flows = httpParser.parse();
			
			//Count the total number of extracted flows.
			int flowcount = 0;
			for(TcpConnection key : flows.keySet()){
				flowcount += flows.get(key).size();
			}
			System.out.println("Parsed " + flowcount + " total flows.");
			
			//Print information about each flow.
			for(TcpConnection key : flows.keySet()){
				
				//Each TCP stream may contain more than one 
				//flow due to persistent connections.
				List<RecordedHttpFlow> flowlist = flows.get(key);
				for(RecordedHttpFlow flow : flowlist){
					
					HttpRequest req = flow.getRequest();
					System.out.println(req.getRequestLine());
					if(req instanceof RecordedHttpRequest){
						//Request with no body.
						System.out.println(((RecordedHttpRequest)req).getUrl());
					} else {
						//Request with a body.
						RecordedHttpEntityEnclosingRequest rreq = 
								(RecordedHttpEntityEnclosingRequest)req;
						System.out.println(rreq.getUrl());
						System.out.println(EntityUtils.toString(rreq.getEntity()));
					}
					
					//A flow could be missing a response, we must check
					//to see if the response is null.
					RecordedHttpResponse resp = flow.getResponse();
					if(resp != null){
						System.out.println(resp.getStatusLine());
						System.out.println("Raw response data:");
						System.out.println(EntityUtils.toString(resp.getEntity()));
						
						//Content-Encoding is gzip or deflate, attempt to decode it.
						HttpEntity decodedent = HttpDecoder.decodeResponse(resp);
						if(decodedent != null){
							System.out.println("Decoded response data:");
							System.out.println(EntityUtils.toString(decodedent));
						}
					}
				}	
			}
		} catch (Exception e) {
			if (log.isErrorEnabled()) {
				log.error(e);
			}
			System.exit(-1);
		}
	}
}
