/*
 * Author(s): Manoj Bharadwaj, Chris Neasbitt
 */

package pcap.reconst.example;

import java.io.File;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import pcap.reconst.beans.TcpConnection;
import pcap.reconst.decoder.HttpDecoder;
import pcap.reconst.output.Http;
import pcap.reconst.output.HttpDecodedOutput;
import pcap.reconst.output.HttpOutput;
import pcap.reconst.reconstructor.JpcapReconstructor;
import pcap.reconst.reconstructor.PacketReassembler;
import pcap.reconst.reconstructor.Reconstructor;
import pcap.reconst.reconstructor.TcpReassembler;

public class FileDataReconstructor {

	private static Log log = LogFactory.getLog(FileDataReconstructor.class);

	public Map<TcpConnection, TcpReassembler> reconstruct(File inputFile,
			Reconstructor reconstructor) throws Exception {
		return reconstructor.reconstruct(inputFile.getAbsolutePath());
	}

	public static void main(String[] args) {
		try {
			FileDataReconstructor fileDataReconstructor = new FileDataReconstructor();
			Map<TcpConnection, TcpReassembler> map = fileDataReconstructor
					.reconstruct(new File(args[0]), new JpcapReconstructor(
							new PacketReassembler()));
			Http http = new Http(map);
			Map<TcpConnection, List<HttpOutput>> httpPackets = http.packetize();
			System.out.println("number of packets " + httpPackets.size());
			for (TcpConnection tcpConnection : httpPackets.keySet()) {
				System.out.println(tcpConnection);
				List<HttpOutput> httpOutputList = httpPackets
						.get(tcpConnection);
				for (HttpOutput httpOutput : httpOutputList) {
					System.out.println(new String(httpOutput.getRequest()
							.getData()));
					System.out.println(new String(httpOutput.getResponse()
							.getData()));
				}
			}
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
			}

		} catch (Exception e) {
			if (log.isErrorEnabled()) {
				log.error(e);
			}
			System.exit(-1);
		}
	}
}
