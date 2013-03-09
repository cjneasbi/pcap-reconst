/*
 * Author: Chris Neasbitt
 */

package pcap.reconst.example;

import java.io.File;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpRequest;
import org.apache.http.util.EntityUtils;

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
			Map<TcpConnection, TcpReassembler> map = fileDataReconstructor
					.reconstruct(new File(args[0]), new JpcapReconstructor(
							new PacketReassembler()));
			HttpFlowParser httpParser = new HttpFlowParser(map);
			Map<TcpConnection, List<RecordedHttpFlow>> flows = httpParser.parse();
			
			int flowcount = 0;
			for(TcpConnection key : flows.keySet()){
				flowcount += flows.get(key).size();
			}
			System.out.println("Parsed " + flowcount + " total flows.");
			
			for(TcpConnection key : flows.keySet()){
				List<RecordedHttpFlow> flowlist = flows.get(key);
				for(RecordedHttpFlow flow : flowlist){
					
					HttpRequest req = flow.getRequest();
					System.out.println(req.getRequestLine());
					if(req instanceof RecordedHttpRequest){
						System.out.println(((RecordedHttpRequest)req).getUrl());
					} else {
						RecordedHttpEntityEnclosingRequest rreq = 
								(RecordedHttpEntityEnclosingRequest)req;
						System.out.println(rreq.getUrl());
						System.out.println(EntityUtils.toString(rreq.getEntity()));
					}
					
					RecordedHttpResponse resp = flow.getResponse();
					if(resp != null){
						System.out.println(resp.getStatusLine());
						System.out.println(EntityUtils.toString(resp.getEntity()));
					}
				}
			}
			
			/*
			HttpDecoder httpDecoder = new HttpDecoder(httpPackets);
			Map<TcpConnection, List<HttpDecodedOutput>> decodedPackets = httpDecoder
					.decodeResponse();
			for (TcpConnection tcpConnection : decodedPackets.keySet()) {
				System.out.println(tcpConnection);
				List<HttpDecodedOutput> decodedList = decodedPackets
						.get(tcpConnection);
				for (HttpDecodedOutput httpDecodedOutput : decodedList) {
					System.out.println(new String(httpDecodedOutput
							.getDecodedResponse().getData()));
				}
			}*/

		} catch (Exception e) {
			if (log.isErrorEnabled()) {
				log.error(e);
			}
			System.exit(-1);
		}
	}
}
