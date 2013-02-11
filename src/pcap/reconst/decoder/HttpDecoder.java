/*
 * Author(s): Manoj Bharadwaj, Chris Neasbitt
 */

package pcap.reconst.decoder;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import pcap.reconst.beans.DecodedData;
import pcap.reconst.beans.InputData;
import pcap.reconst.beans.TcpConnection;
import pcap.reconst.output.HttpDecodedOutput;
import pcap.reconst.output.HttpOutput;

public class HttpDecoder {
	private static Log log = LogFactory.getLog(HttpDecoder.class);

	private Map<TcpConnection, List<HttpOutput>> httpPackets;
	private Decoder decoder = DecoderFactory.getDecoder();

	public HttpDecoder(Map<TcpConnection, List<HttpOutput>> httpPackets) {
		this.httpPackets = httpPackets;
	}

	public Map<TcpConnection, List<HttpDecodedOutput>> decodeResponse() {
		Map<TcpConnection, List<HttpDecodedOutput>> decodedOutput = new HashMap<TcpConnection, List<HttpDecodedOutput>>();
		for (TcpConnection tcpConnection : httpPackets.keySet()) {
			List<HttpDecodedOutput> outlist = new ArrayList<HttpDecodedOutput>();
			List<HttpOutput> httpOutput = httpPackets.get(tcpConnection);
			for (HttpOutput httpPair : httpOutput) {
				outlist.add(decode(httpPair));
			}
			decodedOutput.put(tcpConnection, outlist);
		}
		return decodedOutput;
	}

	private HttpDecodedOutput decode(HttpOutput httpOutput) {
		HttpDecodedOutput httpDecodedOutput = new HttpDecodedOutput(httpOutput);
		InputData response = httpOutput.getResponse();
		DecodedData decodedResponse = new DecodedData(response);
		try {
			decodedResponse = decodeInput(response);
		} catch (Exception e) {
			if (log.isErrorEnabled()) {
				log.error("Error decoding response.", e);
			}
		}
		httpDecodedOutput.setDecodedResponse(decodedResponse);
		if (log.isDebugEnabled()) {
			log.debug(">>>>>>>>>>> decoded response");
			log.debug(decodedResponse.toString());
		}
		return httpDecodedOutput;
	}

	private DecodedData decodeInput(InputData input) {
		DecodedData output = decoder.decode(input.getData(),
				input.getHeaders(), input.getTimestamps());
		if (log.isDebugEnabled()) {
			log.debug(output);
		}
		return output;
	}

}
