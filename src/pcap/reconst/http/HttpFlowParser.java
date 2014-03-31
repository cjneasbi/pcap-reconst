package pcap.reconst.http;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpException;

import pcap.reconst.http.datamodel.RecordedHttpFlow;
import pcap.reconst.http.datamodel.RecordedHttpRequestMessage;
import pcap.reconst.http.datamodel.RecordedHttpResponse;
import pcap.reconst.tcp.MessageMetadata;
import pcap.reconst.tcp.TcpConnection;
import pcap.reconst.tcp.TcpReassembler;

public class HttpFlowParser {

	private static Log log = LogFactory.getLog(HttpFlowParser.class);

	public static final String HTTP_REQ_REGEX = "(GET|POST|HEAD|OPTIONS|PUT|DELETE|TRACE|CONNECT)\\s\\S+\\sHTTP/[1-2]\\.[0-9]\\s";
	public static final String HTTP_RESP_REGEX = "HTTP/[1-2]\\.[0-9]\\s[1-5][0-9][0-9](.[0-9][0-9]?)?\\s";

	private final static int ZERO = 0;

	private Map<TcpConnection, TcpReassembler> map;

	public HttpFlowParser(Map<TcpConnection, TcpReassembler> map) {
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
	
	//TODO fix for the chunked encoding case containing a request in a chunk
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
				//i+2 should give us the end of packet at i+1
				if(i+2 < matchIndexes.size()){
					posC = matchIndexes.get(i+2);
				}
				boolean messageA = matchLocations.get(posA);
				boolean messageB = matchLocations.get(posB);
				boolean errorBetween = assembler.errorBetween(posA, posC);
								
				//if there are errors in the stream then two requests can
				//look pipelined for the fact that a response is missing
				if(messageA && messageB && !errorBetween){
					return true;
				}
			}
		}
		return false;
	}
	
	/*private boolean fixPipelinedSections(List<FlowBuf> pReqSection, List<FlowBuf> pRespSection,
			TcpReassembler assembler){
		if(pReqSection.size() != pRespSection.size()){
			int sizeDiff = Math.abs(pReqSection.size() - pRespSection.size());
			if(log.isInfoEnabled()){
				log.info("Section size difference: " + sizeDiff);
			}
			List<Integer> remove = new ArrayList<Integer>();
			if(pReqSection.size() > pRespSection.size()){ // remove from pReqSection
				if(log.isInfoEnabled()){
					log.info("Removing from request section.");
				}
				for(int i = 0; i < pRespSection.size() - 1; i++){
					if(remove.size() == sizeDiff){
						break;
					}
					int begin = pRespSection.get(i).respStart;
					int end = pRespSection.get(i+1).respEnd;
					if(assembler.errorBetween(begin, end)){
						remove.add(i+1);
					}
				}
				if(remove.size() == sizeDiff){
					for(int index : remove){
						pReqSection.remove(index);
					}
					return true;
				} else {
					if(log.isInfoEnabled()){
						log.info("Unable to find enough requests to remove: " + remove.size());
					}
				}
			} else { // remove from pRespSection
				if(log.isInfoEnabled()){
					log.info("Removing from response section.");
				}
				for(int i = 0; i < pReqSection.size() - 1; i++){
					if(remove.size() == sizeDiff){
						break;
					}
					int begin = pReqSection.get(i).reqStart;
					int end = pReqSection.get(i+1).reqEnd;
					if(assembler.errorBetween(begin, end)){
						remove.add(i+1);
					}
				}
				if(remove.size() == sizeDiff){
					for(int index : remove){
						pRespSection.remove(index);
					}
					return true;
				} else {
					if(log.isInfoEnabled()){
						log.info("Unable to find enough responses to remove: " + remove.size());
					}
				}
			}
		}
		return false;
	}*/
	
	private List<FlowBuf> parsePipelinedFlows(String buf, TcpReassembler assembler){
		List<FlowBuf> retval = new ArrayList<FlowBuf>();
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
		
			List<FlowBuf> pReqSection = new ArrayList<FlowBuf>();
			List<FlowBuf> pRespSection = new ArrayList<FlowBuf>();
			FlowBuf singReqFlow = null;
			for(int i = 0; i < matchIndexes.size(); i++){
				boolean current = matchLocations.get(matchIndexes.get(i));
				if(i + 1 < matchIndexes.size()){
					//TODO i should probably be i+1 in the following line, check and fix
					boolean next = matchLocations.get(matchIndexes.get(i + 1));
					if(current){
						FlowBuf reqchunk = new FlowBuf();
						reqchunk.reqStart = matchIndexes.get(i);
						reqchunk.reqEnd = matchIndexes.get(i+1);
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
						FlowBuf respchunk = new FlowBuf();
						respchunk.respStart = matchIndexes.get(i);
						respchunk.respEnd = matchIndexes.get(i+1);
						if(next){
							//if response then request
							if(singReqFlow != null){								
								retval.add(this.mergeFlowBuf(singReqFlow, respchunk));
								singReqFlow = null;
							} else {
								pRespSection.add(respchunk);
							}
							if(pReqSection.size() != pRespSection.size()){
								if(log.isDebugEnabled()){
									log.debug("Unequal pipeline sections. Returning parsed stream section.");
								}
								return retval;
								/*if(log.isWarnEnabled()){
									log.warn("Unequal pipeline sections. Attempting to fix.");
								}
								if(fixPipelinedSections(pReqSection, pRespSection, assembler)){
									if(log.isInfoEnabled()){
										log.info("Fixed unequal pipeline sections.");
									}
								} else {
									throw new RuntimeException("Unable to fix unequal pipeline sections.");
								}*/
							}
						} else {
							//if response then response
							if(pReqSection.size() > 0){
								pRespSection.add(respchunk);
							} else {
								//throw new RuntimeException("Two adjacent responses in error.");
								if(log.isDebugEnabled()){
									log.debug("Two adjacent responses in error. Returning parsed stream section.");
								}
								return retval;
							}
						}
						if(pReqSection.size() == pRespSection.size()){
							for(int q = 0; q < pReqSection.size(); q++){
								retval.add(this.mergeFlowBuf(pReqSection.get(q), pRespSection.get(q)));
							}
							pReqSection.clear();
							pRespSection.clear();
						}
					}
				} else {
					//i = len - 1
					if(current){ // if request
						FlowBuf reqchunk = new FlowBuf();
						reqchunk.reqStart = matchIndexes.get(i);
						reqchunk.reqEnd = buf.length();
						pReqSection.add(reqchunk);
						for(FlowBuf req : pReqSection){
							retval.add(req);
						}
					} else { //if response
						FlowBuf respchunk = new FlowBuf();
						respchunk.respStart = matchIndexes.get(i);
						respchunk.respEnd = buf.length();
						if(singReqFlow != null){ //single flow							
							retval.add(mergeFlowBuf(singReqFlow, respchunk));
							singReqFlow = null;
						} else if (pReqSection.size() > 0) { //pipelined request section
							pRespSection.add(respchunk);
						} else {
							//throw new RuntimeException("Single unmatched response");
							if(log.isDebugEnabled()){
								log.debug("Single unmatched response. Returning parsed stream section.");
							}
							return retval;
						}
					}
					
					//if at the end of the stream, should be the end of the pipelined section
					if(pReqSection.size() == pRespSection.size()){
						//if pReqSection and pRespSection are empty then the loop is never executed
						for(int q = 0; q < pReqSection.size(); q++){							
							retval.add(mergeFlowBuf(pReqSection.get(q), pRespSection.get(q)));
						}
						pReqSection.clear();
						pRespSection.clear();
					} else {
						if(pReqSection.size() > pRespSection.size()){
							//throw new RuntimeException("Incompleted pipelined response section.");
							if(log.isDebugEnabled()){
								log.debug("Incomplete pipelined response section. Returning parsed stream section.");
							}
						} else {
							//throw new RuntimeException("Incompleted pipelined request section.");
							if(log.isDebugEnabled()){
								log.debug("Incomplete pipelined request section. Returning parsed stream section.");
							}
						}
					}
				}
			}
		}
		return retval;
	}
	
	
	/*private List<List<String>> parsePipelinedFlows(String buf){
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
					//TODO i should probably be i+1 in the following line, check and fix
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
	}*/
	
	private List<Integer> matchStartLocations(String buf, String regex){
		List<Integer> indexes = new ArrayList<Integer>();
		Pattern pat = Pattern.compile(regex);
		Matcher matcher = pat.matcher(buf);
		while (matcher.find()) {
			indexes.add(matcher.start());
		}
		return indexes;
	}

	private List<FlowBuf> splitFlows(String buf) {
		List<FlowBuf> retval = new ArrayList<FlowBuf>();
		Map<Integer, Boolean> matchLocations = this.buildMessageStartIndex(buf);
		List<Integer> matchIndexes = new ArrayList<Integer>(matchLocations.keySet());
		Collections.sort(matchIndexes);
		
		if(matchIndexes.size() > 0){
			
			//get rid of any leading responses
			while(!matchLocations.get(matchIndexes.get(ZERO))){
				matchIndexes.remove(ZERO);
				if(matchIndexes.isEmpty()){
					break;
				}
			}
			
			if(log.isDebugEnabled()){
				log.debug("Number of match indexes: " + matchIndexes.size());
			}
			
			FlowBuf temp = null;
			for(int i = 0; i < matchIndexes.size(); i++){
				boolean current = matchLocations.get(matchIndexes.get(i));
				if(i + 1 < matchIndexes.size()){
					boolean next = matchLocations.get(matchIndexes.get(i + 1));
					if(current){ //is request
						if(!next){ //is response
							if(temp == null){
								temp = new FlowBuf();
								temp.reqStart = matchIndexes.get(i);
								temp.reqEnd = matchIndexes.get(i + 1);
							} else {
								throw new RuntimeException("FlowBuf should be null at this point.");
								// FlowBuf should be null, error
							}
						} else { //is request
							if(log.isDebugEnabled()){
								log.debug("Two adjacent requests in non pipelined flow.  " +
										"Request starting at index " + matchIndexes.get(i) + " has no response.");
							}
							temp = new FlowBuf();
							temp.reqStart = matchIndexes.get(i);
							temp.reqEnd = matchIndexes.get(i + 1);
							retval.add(temp);
							temp = null;
							// two requests back to back, error
						}
					} else { //is response
						if(next){ //is request
							if(temp != null){
								temp.respStart = matchIndexes.get(i);
								temp.respEnd = matchIndexes.get(i+1);
								retval.add(temp);
								temp = null;
							} else {
								throw new RuntimeException("FlowBuf should not be null at this point.");
								// FlowBuf should not be null, error
							}
						} else { // is response
							if(log.isDebugEnabled()){
								log.debug("Two adjacent responses in non pipelined flow.  " +
										"Response starting at index " + matchIndexes.get(i+1) + " has no request.");
							}
							temp.respStart = matchIndexes.get(i);
							temp.respEnd = matchIndexes.get(i+1);
							retval.add(temp);
							temp = null;
							i++; //skips the erroneous response
							// two responses back to back, error
						}
					}
				} else {
					if(current){ // is request
						if(temp == null){
							temp = new FlowBuf();
							temp.reqStart = matchIndexes.get(i);
							temp.reqEnd = buf.length();
							retval.add(temp);
						} else {
							throw new RuntimeException("FlowBuf should be null at this point.");
							// FlowBuf should be equal to null, error
						}
					} else { // is response
						if(temp != null){
							temp.respStart = matchIndexes.get(i);
							temp.respEnd = buf.length();
							retval.add(temp);
						} else {
							throw new RuntimeException("FlowBuf should not be null at this point.");
							// FlowBuf should not be equal to null, error
						}
					}
				}
			}
		}
		
		return retval;
	}
	
	
	/*private List<String> splitFlows(String buf) {
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
	}*/

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

	/*private int responseStart(String buf) {
		Pattern pat = Pattern.compile(HTTP_RESP_REGEX);
		Matcher matcher = pat.matcher(buf);
		if (matcher.find()) {
			return matcher.start();
		}
		return -1;
	}*/

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

	/*private boolean hasResponseData(String buf) {
		return this.hasDesiredData(buf, HTTP_RESP_REGEX);
	}*/

	private boolean hasDesiredData(String buf, String regex) {
		Pattern pat = Pattern.compile(regex);
		Matcher matcher = pat.matcher(buf);
		return matcher.find();
	}
	
	private List<RecordedHttpFlow> parseFlows(TcpConnection connection, TcpReassembler assembler) {
		String flowbuf = assembler.getOrderedPacketData();
		List<RecordedHttpFlow> outputlist = new ArrayList<RecordedHttpFlow>();
		if (this.hasRequestData(flowbuf)) {

			List<FlowBuf> flows = null;
			if(isPipelined(assembler)){
				if(log.isDebugEnabled()){
					log.debug("Parsing pipelined stream. " + connection);
				}
				flows = parsePipelinedFlows(flowbuf, assembler);
				
			} else {
				if(log.isDebugEnabled()){
					log.debug("Parsing non-pipelined stream. " + connection);
				}
				flows = splitFlows(flowbuf);
			}
			for (FlowBuf flow : flows) {
				try {
					RecordedHttpFlow httpOutput = toHttp(flow, assembler);
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
	

	/*private List<RecordedHttpFlow> parseFlows(TcpConnection connection, TcpReassembler assembler) {
		String flowbuf = assembler.getOrderedPacketData();
		List<RecordedHttpFlow> outputlist = new ArrayList<RecordedHttpFlow>();
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
					RecordedHttpFlow httpOutput = toHttp(flow, assembler);
					outputlist.add(httpOutput);
				} catch (Exception e) {
					if (log.isErrorEnabled()) {
						log.error("", e);
					}
				}
			}
		}
		return outputlist;
	}*/

	public Map<TcpConnection, List<RecordedHttpFlow>> parse() {
		Map<TcpConnection, List<RecordedHttpFlow>> httpPackets = 
				new HashMap<TcpConnection, List<RecordedHttpFlow>>();

		for (TcpConnection connection : map.keySet()) {
			try{
				List<RecordedHttpFlow> flows = parseFlows(connection, map.get(connection));
				if(flows.size() > 0){
					httpPackets.put(connection, flows);
				} else {
					if(log.isDebugEnabled()){
						log.debug("No HTTP flows found in stream: " + connection);
					}
				}
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
	
	private RecordedHttpFlow toHttp(FlowBuf flow, TcpReassembler assembler) throws IOException, HttpException {
		if (log.isDebugEnabled()) {
			log.debug("Processing flow " + flow);
		}
		String rawdata = null;
		if (flow.hasRequestData()) {
			rawdata = assembler.getOrderedPacketData().substring(
					flow.reqStart, flow.reqEnd);
			
			RecordedHttpRequestMessage request;
			RecordedHttpResponse response = null;

			if (flow.hadResponseData()) {
				rawdata += assembler.getOrderedPacketData().substring(
						flow.respStart, flow.respEnd);
				request = getRequest(flow, assembler);
				response = getResponse(flow, assembler);
			} else {
				request = getRequest(flow, assembler);
			}
			return new RecordedHttpFlow(rawdata.getBytes(), request, response);
		}
		return null;
	}
	
	
	/*private RecordedHttpFlow toHttp(String flow, TcpReassembler assembler) throws IOException, HttpException {
		if (log.isDebugEnabled()) {
			log.debug("total length " + flow.length());
		}
		if (this.hasRequestData(flow)) {
			RecordedHttpRequestMessage request;
			RecordedHttpResponse response = null;

			if (this.hasResponseData(flow)) {
				int responseIndex = this.responseStart(flow);
				request = getRequest(flow, responseIndex, assembler);
				response = getResponse(flow, responseIndex, assembler);
			} else {
				request = getRequest(flow, flow.length(), assembler);
			}
			return new RecordedHttpFlow(flow.getBytes(), request, response);
		}
		return null;
	}*/
	
	private RecordedHttpRequestMessage getRequest(FlowBuf flow, TcpReassembler assembler) throws IOException, HttpException{
		String reqstring = assembler.getOrderedPacketData().substring(
				flow.reqStart, flow.reqEnd);
		MessageMetadata mdata = assembler
				.getMessageMetadata(flow.reqStart, flow.reqEnd);
		return (RecordedHttpRequestMessage)RecordedHttpMessageParser.
				parseRecordedRequest(reqstring, mdata);
	}
	
	/*private RecordedHttpRequestMessage getRequest(String data, int responseIndex, 
			TcpReassembler assembler) throws IOException, HttpException{
		String reqstring = data.substring(ZERO, responseIndex);
		MessageMetadata mdata = assembler
				.getMessageMetadata(new String(reqstring));
		return (RecordedHttpRequestMessage)RecordedHttpMessageParser.
				parseRecordedRequest(reqstring, mdata);
	}*/
	
	private RecordedHttpResponse getResponse(FlowBuf flow, 
			TcpReassembler assembler) throws IOException, HttpException{
		String respstring = assembler.getOrderedPacketData().substring(
				flow.respStart, flow.respEnd);
		MessageMetadata mdata = assembler
				.getMessageMetadata(flow.respStart, flow.respEnd);
		return (RecordedHttpResponse)RecordedHttpMessageParser.
				parseRecordedResponse(respstring, mdata);
	}
	
	/*private RecordedHttpResponse getResponse(String data, int responseIndex, 
			TcpReassembler assembler) throws IOException, HttpException{
		String respstring = data.substring(responseIndex);
		MessageMetadata mdata = assembler
				.getMessageMetadata(new String(respstring));
		return (RecordedHttpResponse)RecordedHttpMessageParser.
				parseRecordedResponse(respstring, mdata);
	}*/
	
	public FlowBuf mergeFlowBuf(FlowBuf reqChunk, FlowBuf respChunk){
		FlowBuf retval = new FlowBuf();
		retval.reqStart = reqChunk.reqStart;
		retval.reqEnd = reqChunk.reqEnd;
		retval.respStart = respChunk.respStart;
		retval.respEnd = respChunk.respEnd;
		return retval;
	}
	
	private class FlowBuf{
		public int reqStart = -1, reqEnd = -1, respStart = -1, respEnd = -1;
		
		public boolean hasRequestData(){
			return reqStart != -1 && reqEnd != -1;
		}
		
		public boolean hadResponseData(){
			return respStart != -1 && respEnd != -1;
		}
		
		@Override
		public String toString(){
			return "Request Start: " + reqStart + " Request End: " + reqEnd + " Response Start: " + 
					respStart + " Response End: " + respEnd;
		}
	}

}
