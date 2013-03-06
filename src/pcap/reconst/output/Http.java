/*
 * Author(s): Manoj Bharadwaj, Chris Neasbitt
 */

package pcap.reconst.output;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import pcap.reconst.beans.HTTPRequest;
import pcap.reconst.beans.HTTPResponse;
import pcap.reconst.beans.MessageMetadata;
import pcap.reconst.beans.TcpConnection;
import pcap.reconst.reconstructor.TcpReassembler;

public class Http {
	private static Log log = LogFactory.getLog(Http.class);

	public static final String HTTP_REQ_REGEX = "(GET|POST|HEAD|OPTIONS|PUT|DELETE|TRACE|CONNECT)\\s\\S+\\sHTTP/[1-2]\\.[0-9]\\s";
	public static final String HTTP_RESP_REGEX = "HTTP/[1-2]\\.[0-9]\\s[1-5][0-9][0-9](.[0-9][0-9]?)?\\s";

	private final static int ZERO = 0;

	private Map<TcpConnection, TcpReassembler> map;

	public Http(Map<TcpConnection, TcpReassembler> map) {
		this.map = map;
	}
	
	private Map<Integer, Boolean> buildMessageStartIndex(String buf){
		List<Integer> reqIndexes = matchStartLocations(buf, HTTP_REQ_REGEX);
		List<Integer> respIndexes = matchStartLocations(buf, HTTP_RESP_REGEX);
		Map<Integer, Boolean> matchLocations = new HashMap<Integer, Boolean>();
		for(Integer key : reqIndexes){
			matchLocations.put(key, true); //true = request
		}
		for(Integer key : respIndexes){
			matchLocations.put(key, false); //false = response
		}
		return matchLocations;
	}
	
	//TODO fix for the chunked encoding case
	private boolean isPipelined(TcpReassembler assembler){
		Map<Integer, Boolean> matchLocations = this.buildMessageStartIndex(
				assembler.getOrderedPacketData());
		List<Integer> matchIndexes = new ArrayList<Integer>(matchLocations.keySet());
		Collections.sort(matchIndexes);
		
		if(matchIndexes.size() > 1){
			for(int i = 0; i < matchIndexes.size() - 1; i++){
				int posA = matchIndexes.get(i);
				int posB = matchIndexes.get(i+1);
				int posC = assembler.getOrderedPacketData().length();
				//i+3 should give us the end of packet after i + 1
				if(i+3 < matchIndexes.size()){
					posC = matchIndexes.get(i+3);
				}
				boolean messageA = matchLocations.get(posA);
				boolean messageB = matchLocations.get(posB);
				
				//if there are errors in the stream then two requests can
				//look pipelined for the fact that a response is missing
				if(messageA && messageB && !assembler.errorBetween(posA, posC)){
					return true;
				}
			}
		}
		return false;
	}
	
	private List<List<String>> parsePipelinedFlows(String buf){
		List<List<String>> retval = new ArrayList<List<String>>();
		Map<Integer, Boolean> matchLocations = this.buildMessageStartIndex(buf);
		List<Integer> matchIndexes = new ArrayList<Integer>(matchLocations.keySet());
		Collections.sort(matchIndexes);
		
		if(log.isDebugEnabled()){
			String logval = "Match Locations:\n";
			for(int index : matchIndexes){
				logval += index + " " + (matchLocations.get(index) ? "Request" : "Response") + "\n";
			}
			log.debug(logval);
		}
		
		if(matchIndexes.size() > 0){
			//get rid of any leading responses
			while(!matchLocations.get(matchIndexes.get(ZERO))){
				matchIndexes.remove(ZERO);
				if(matchIndexes.isEmpty()){
					break;
				}
			}
		
			List<String> pReqSection = new ArrayList<String>();
			List<String> pRespSection = new ArrayList<String>();
			String singReqFlow = null;
			for(int i = 0; i < matchIndexes.size(); i++){
				boolean current = matchLocations.get(matchIndexes.get(i));
				if(i + 1 < matchIndexes.size()){
					boolean next = matchLocations.get(matchIndexes.get(i));
					if(current){
						String reqchunk = buf.substring(matchIndexes.get(i), matchIndexes.get(i+1));
						if(next){
							//if request then request
							pReqSection.add(reqchunk);
						} else {
							//if request then response
							if(pReqSection.size() > 0){
								pReqSection.add(reqchunk);
							} else {
								singReqFlow=reqchunk;
							}
						}
					} else {
						String respchunk = buf.substring(matchIndexes.get(i), matchIndexes.get(i+1));
						if(next){
							//if response then request
							if(singReqFlow != null){
								List<String> flow = new ArrayList<String>();
								flow.add(singReqFlow);
								flow.add(respchunk);
								retval.add(flow);
								singReqFlow = null;
							} else {
								pRespSection.add(respchunk);
							}
							if(pReqSection.size() != pRespSection.size()){
								throw new RuntimeException("Unequal pipeline sections.");
							}
						} else {
							//if response then response
							if(pReqSection.size() > 0){
								pRespSection.add(respchunk);
							} else {
								throw new RuntimeException("Two adjacent responses in error.");
							}
						}
						if(pReqSection.size() == pRespSection.size()){
							for(int q = 0; q < pReqSection.size(); q++){
								List<String> flow = new ArrayList<String>();
								flow.add(pReqSection.get(q));
								flow.add(pRespSection.get(q));
								retval.add(flow);
							}
							pReqSection.clear();
							pRespSection.clear();
						}
					}
				} else {
					//i = len - 1
					if(current){ // if request
						String reqchunk = buf.substring(matchIndexes.get(i));
						pReqSection.add(reqchunk);
						for(String req : pReqSection){
							List<String> flow = new ArrayList<String>();
							flow.add(req);
							flow.add(null);
							retval.add(flow);
						}
					} else { //if response
						String respchunk = buf.substring(matchIndexes.get(i));
						if(singReqFlow != null){ //single flow
							List<String> flow = new ArrayList<String>();
							flow.add(singReqFlow);
							flow.add(respchunk);
							retval.add(flow);
							singReqFlow = null;
						} else if (pReqSection.size() > 0) { //pipelined request section
							pRespSection.add(respchunk);
						} else {
							throw new RuntimeException("Single unmatched response");
						}
					}
					
					//if at the end of the stream, should be the end of the pipelined section
					if(pReqSection.size() == pRespSection.size()){
						//if pReqSection and pRespSection are empty then the loop is never executed
						for(int q = 0; q < pReqSection.size(); q++){
							List<String> flow = new ArrayList<String>();
							flow.add(pReqSection.get(q));
							flow.add(pRespSection.get(q));
							retval.add(flow);
						}
						pReqSection.clear();
						pRespSection.clear();
					} else {
						if(pReqSection.size() > pRespSection.size()){
							throw new RuntimeException("Incompleted pipelined response section.");
						} else {
							throw new RuntimeException("Incompleted pipelined request section.");
						}
					}
				}
	
			}
		}
		return retval;
	}
	
	private List<Integer> matchStartLocations(String buf, String regex){
		List<Integer> indexes = new ArrayList<Integer>();
		Pattern pat = Pattern.compile(regex);
		Matcher matcher = pat.matcher(buf);
		while (matcher.find()) {
			indexes.add(matcher.start());
		}
		return indexes;
	}

	private List<String> splitFlows(String buf) {
		List<String> retval = new ArrayList<String>();
		List<Integer> indexes = matchStartLocations(buf, HTTP_REQ_REGEX);
		for (int i = 0; i < indexes.size(); i++) {
			if (i == indexes.size() - 1) {
				retval.add(buf.substring(indexes.get(i)));
			} else {
				retval.add(buf.substring(indexes.get(i), indexes.get(i + 1)));
			}
		}
		return retval;
	}

	@SuppressWarnings("unused")
	private int numRequests(String buf) {
		int retval = this.numMatches(buf, HTTP_REQ_REGEX);
		if (log.isDebugEnabled()) {
			log.debug("Number of Requests: " + retval);
		}
		return retval;
	}

	@SuppressWarnings("unused")
	private int numResponses(String buf) {
		int retval = this.numMatches(buf, HTTP_RESP_REGEX);
		if (log.isDebugEnabled()) {
			log.debug("Number of Responses: " + retval);
		}
		return retval;
	}

	private int responseStart(String buf) {
		Pattern pat = Pattern.compile(HTTP_RESP_REGEX);
		Matcher matcher = pat.matcher(buf);
		if (matcher.find()) {
			return matcher.start();
		}
		return -1;
	}

	private int numMatches(String buf, String regex) {
		int retval = 0;
		Pattern pat = Pattern.compile(regex);
		Matcher matcher = pat.matcher(buf);
		while (matcher.find()) {
			retval++;
		}
		return retval;
	}

	private boolean hasRequestData(String buf) {
		return this.hasDesiredData(buf, HTTP_REQ_REGEX);
	}

	private boolean hasResponseData(String buf) {
		return this.hasDesiredData(buf, HTTP_RESP_REGEX);
	}

	private boolean hasDesiredData(String buf, String regex) {
		Pattern pat = Pattern.compile(regex);
		Matcher matcher = pat.matcher(buf);
		return matcher.find();
	}

	private List<HttpOutput> packetizeFlow(TcpConnection connection, TcpReassembler assembler) {
		String flowbuf = assembler.getOrderedPacketData();
		List<HttpOutput> outputlist = new ArrayList<HttpOutput>();
		if (this.hasRequestData(flowbuf)) {

			List<String> flows = null;
			if(isPipelined(assembler)){
				if(log.isDebugEnabled()){
					log.debug("Parsing pipelined stream. " + connection);
				}
				List<List<String>> piperesult = this.parsePipelinedFlows(flowbuf);
				flows = new ArrayList<String>();
				//combine the flow tups
				for(List<String> flowtup : piperesult){
					String flowval = flowtup.get(ZERO);
					if(flowtup.size() > 1 && flowtup.get(1) != null){
						flowval += flowtup.get(1);
					}
					flows.add(flowval);
				}
			} else {
				flows = splitFlows(flowbuf);
			}
			for (String flow : flows) {
				try {
					HttpOutput httpOutput = toHttp(flow, assembler);
					outputlist.add(httpOutput);
				} catch (Exception e) {
					if (log.isErrorEnabled()) {
						log.error("", e);
					}
				}
			}
		}
		return outputlist;
	}

	public Map<TcpConnection, List<HttpOutput>> packetize() {
		Map<TcpConnection, List<HttpOutput>> httpPackets = new HashMap<TcpConnection, List<HttpOutput>>();

		for (TcpConnection connection : map.keySet()) {
			try{
				httpPackets
						.put(connection, this.packetizeFlow(connection, map.get(connection)));
				if (log.isDebugEnabled()) {
					log.debug("Processed stream: " + connection);
				}
			} catch (Exception e) {
				if(log.isErrorEnabled()){
					log.error("Error processing stream: " + connection, e);
				}
			}
		}
		return httpPackets;
	}

	private HttpOutput toHttp(String flow, TcpReassembler assembler) {
		if (log.isDebugEnabled()) {
			log.debug("total length " + flow.length());
		}
		if (this.hasRequestData(flow)) {
			HTTPRequest request;
			HTTPResponse response = null;

			if (this.hasResponseData(flow)) {
				int responseIndex = this.responseStart(flow);
				request = getRequest(flow, responseIndex, assembler);
				int responseLength = flow.length() - responseIndex;
				response = getResponse(flow, responseLength, responseIndex,
						assembler);
			} else {
				request = getRequest(flow, flow.length(), assembler);
			}
			return new HttpOutput(flow.getBytes(), request, response);
		}
		return null;
	}

	private HTTPResponse getResponse(String data, int responseLength,
			int responseIndex, TcpReassembler assembler) {
		byte[] response = data.substring(responseIndex).getBytes();
		MessageMetadata mdata = assembler.getMessageMetadata(new String(
				response));
		HTTPResponse responseobj = new HTTPResponse(response, mdata);
		if (log.isDebugEnabled()) {
			log.debug(responseobj.getHeaders());
			int responseContentLength = responseobj.getHeaders()
					.getContentLength();
			log.debug(responseContentLength);
		}
		return responseobj;
	}

	private HTTPRequest getRequest(String data, int responseIndex,
			TcpReassembler assembler) {
		byte[] request = data.substring(ZERO, responseIndex).getBytes();
		MessageMetadata mdata = assembler
				.getMessageMetadata(new String(request));
		HTTPRequest requestobj = new HTTPRequest(request, mdata);
		if (log.isDebugEnabled()) {
			log.debug(requestobj.getHeaders());
			int requestContentLength = requestobj.getHeaders()
					.getContentLength();
			log.debug(requestContentLength);
		}
		return requestobj;
	}
}
