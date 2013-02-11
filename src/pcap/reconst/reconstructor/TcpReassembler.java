/*
 * Author: Chris Neasbitt
 */

package pcap.reconst.reconstructor;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import pcap.reconst.beans.TcpConnection;
import pcap.reconst.beans.TimestampPair;
//import pcap.reconst.beans.TcpData;
//import pcap.reconst.beans.TcpFragment;
import pcap.reconst.beans.TcpSequenceCounter;
import pcap.reconst.beans.packet.PlaceholderTcpPacket;
import pcap.reconst.beans.packet.TcpPacket;

//import java.io.ByteArrayOutputStream;
//import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class TcpReassembler {
	private static Log log = LogFactory.getLog(TcpReassembler.class);
	
    private TcpSequenceCounter reqCounter = null, respCounter = null;
    private List<TcpPacket> orderedPackets = new ArrayList<TcpPacket>();
    private List<Integer> reqIndexes = new ArrayList<Integer>();
    private List<Integer> respIndexes = new ArrayList<Integer>();
    private String packetData = null;
    private Map<Integer, Integer> packetPositions = new HashMap<Integer, Integer>();
    
    private boolean rebuildData = true;
    
    public boolean isIncomplete() {
    	for(TcpPacket packet : orderedPackets){
    		if(packet instanceof PlaceholderTcpPacket){
    			return true;
    		}
    	}
        return false;
    }

    public boolean isEmpty() {
        return orderedPackets.isEmpty();
    }
    
    public String getOrderedPacketData(){
    	if(rebuildData || packetData == null){
    		buildPacketData();
    		rebuildData = false;
    	}
    	return packetData;
    }
    
    public void buildPacketData(){
    	StringBuffer buf = new StringBuffer();
    	for(int i = 0; i < orderedPackets.size(); i++){
    		byte[] data = orderedPackets.get(i).getData();
    		if(data != null && data.length > 0){
    			int startpos = buf.length();
    			buf.append(new String(data));
    			packetPositions.put(buf.length(), i);
    			if(log.isInfoEnabled()){
    				log.info("Start position: " + startpos + " End position: " + 
    						buf.length() + "\n" + new String(data));
    			}
    		}
    	}
    	packetData = buf.toString();
    }
    
    
    public TimestampPair getTimestampRange(String needle){
    	if(rebuildData || packetData == null){
    		buildPacketData();
    		rebuildData = false;
    	}
    	
    	int beginIndex = this.packetData.indexOf(needle);
    	int endIndex = beginIndex + needle.length();
    	
    	if(log.isInfoEnabled()){
    		log.info("Find timestamp for:\n" + needle + 
    				"\nbegin index: " + beginIndex + " end index: " + endIndex);
    	}
    	
    	double startTS = -1.0, endTS = -1.0;
    	
    	List<Integer> positions = new ArrayList<Integer>(packetPositions.keySet());
    	Collections.sort(positions);
    	
    	for(int pos : positions){
    		if(startTS < 0.0 && beginIndex < pos){
    			TcpPacket packet = orderedPackets.get(packetPositions.get(pos));
    			startTS = Double.parseDouble(packet.getTimestampSec() + "." + 
    					packet.getTimestampUSec());
    		}
    		if(endTS < 0.0 && endIndex <= pos){
    			TcpPacket packet = orderedPackets.get(packetPositions.get(pos));
    			endTS = Double.parseDouble(packet.getTimestampSec() + "." + 
    					packet.getTimestampUSec());
    		}
    	}
    	
    	if(log.isDebugEnabled()){
    		log.debug("start: " + startTS + " end: " + endTS);
    	}
    	
    	
    	if(startTS > -1.0){
    		return new TimestampPair(startTS, endTS);
    	}
    	
    	return null;
    }

    public TcpReassembler(){}

    /*
     * The main function of the class receives a tcp packet and reconstructs the stream
     */
    public void reassemblePacket(TcpPacket tcpPacket) throws Exception {
    	if(log.isDebugEnabled()){
    		log.debug(String.format("captured_len = %d, len = %d, headerlen = %d, datalen = %d", 
    				tcpPacket.getCaptureLength(), tcpPacket.getLength(), tcpPacket.getHeaderLength(), 
    				tcpPacket.getDataLength()));
    	}
        reassembleTcp(new TcpConnection(tcpPacket), tcpPacket);
    }

    private void reassembleTcp(TcpConnection tcpConnection, TcpPacket packet) throws Exception {
        if(log.isDebugEnabled()){
	    	log.debug(String.format("sequence=%d ack_num=%d length=%d dataLength=%d synFlag=%s %s srcPort=%s %s dstPort=%s", 
	        		packet.getSequence(), packet.getAckNum(), packet.getLength(), packet.getDataLength(), packet.getSyn(), tcpConnection.getSrcIp(), tcpConnection.getSrcPort(), 
	        		tcpConnection.getDstIp(), tcpConnection.getDstPort()));
        }

        boolean first = false;
        PacketType packetType = null;

        // Now check if the packet is for this connection. 
        InetAddress srcIp = tcpConnection.getSrcIp();
        int srcPort = tcpConnection.getSrcPort();

        // Check to see if we have seen this source IP and port before.
        // check both source IP and port; the connection might be between two different ports on the same machine... 
        if(reqCounter == null) {
            reqCounter = new TcpSequenceCounter(srcIp, srcPort);
            packetType = PacketType.Request;
            first = true;
        } else {
        	if (reqCounter.getAddress().equals(srcIp) && reqCounter.getPort() == srcPort) {
                // check if request is already being handled... this is a fragmented packet
                packetType = PacketType.Request;
            } else {
            	if (respCounter == null) {
                    respCounter = new TcpSequenceCounter(srcIp, srcPort);
                    packetType = PacketType.Response;
                    first = true;
            	} else if (respCounter.getAddress().equals(srcIp) && respCounter.getPort() == srcPort) {    
                    // check if response is already being handled... this is a fragmented packet
                    packetType = PacketType.Response;
                }
            }
        }

        if (packetType == null) {
            throw new Exception("ERROR in TcpReassembler: Too many or too few addresses!");
        }
        
        if(log.isDebugEnabled()){
        	log.debug((isRequest(packetType) ? "request" : "response") + " packet...");
        }
        
        TcpSequenceCounter currentCounter = isRequest(packetType) ? reqCounter : respCounter;
        updateSequence(first, currentCounter, packet, packetType);
    }


    private boolean isRequest(PacketType packetType) {
        return PacketType.Request == packetType;
    }
    
    private void updateSequence(boolean first, TcpSequenceCounter tcpSeq, 
    		TcpPacket packet, PacketType type) throws IOException {
        // figure out sequence number stuff
        if (first) {
            // this is the first time we have seen this src's sequence number
            tcpSeq.setSeq(packet.getSequence() + (long)packet.getDataLength());
            if (packet.getSyn()) {
                tcpSeq.incrementSeq();
            }
            // add to ordered packets
            addOrderedPacket(packet, type);
            return;
        }
        
        // if we are here, we have already seen this src, let's try and figure out if this packet is in the right place
        if (packet.getSequence() < tcpSeq.getSeq()) {
        	if(!this.checkPlaceholders(packet, type)){
        		if(log.isDebugEnabled()){
        			log.debug("Unable to place packet.\n" + packet);
        		}
        	}
        }

        if (packet.getSequence() == tcpSeq.getSeq()) {
            // packet in sequence
            tcpSeq.addToSeq((long)packet.getDataLength());
            if (packet.getSyn()) {
                tcpSeq.incrementSeq();
            }
            addOrderedPacket(packet, type);
        } else {
            // out of order packet
            if (packet.getDataLength() > 0 && packet.getSequence() > tcpSeq.getSeq()) {
            	PlaceholderTcpPacket ppacket = new PlaceholderTcpPacket(packet.getSourceIP(), 
            			packet.getSourcePort(), packet.getDestinationIP(), packet.getDestinationPort(), 
            			tcpSeq.getSeq(), (int)(packet.getSequence() - this.getLastOrderedSequence(type)));
            	this.addOrderedPacket(ppacket, type);
            	this.addOrderedPacket(packet, type);
            	tcpSeq.setSeq(packet.getSequence());
            }
        }
    }

    private boolean checkPlaceholders(TcpPacket packet, PacketType type){
    	boolean retval = false;
    	for(Integer index : this.getPacketIndexes(type)){
    		TcpPacket pospacket = orderedPackets.get(index);
    		if(pospacket instanceof PlaceholderTcpPacket){    			
    			//overlap placeholder beginning
    			if(packet.getSequence() < pospacket.getSequence() && 
    					(packet.getSequence() + packet.getLength()) < 
    					(pospacket.getSequence() + pospacket.getLength())){
    				if(log.isDebugEnabled()){
    					log.debug("Overlap placeholder beginning.\n" + packet);
    				}
    				//retval = true;
    				//break;
    			}
    			
    			//overlap placeholder ending
    			if(packet.getSequence() > pospacket.getSequence() && 
    					(packet.getSequence() + packet.getLength()) > 
    					(pospacket.getSequence() + pospacket.getLength())){
    				if(log.isDebugEnabled()){
    					log.debug("Overlap placeholder ending.\n" + packet);
    				}
    				//retval = true;
    				//break;
    			}
    			
    			//in the middle of the place holder
    			if(packet.getSequence() >= pospacket.getSequence() && 
     					(packet.getSequence() + packet.getLength()) <= 
    					(pospacket.getSequence() + pospacket.getLength())){
        			
    				//exactly fits a place holder
        			if(packet.getSequence() == pospacket.getSequence() && 
        					packet.getLength() == pospacket.getLength()){
        				this.setOrderedPacket(packet, type, index);
        			} else {
        				long leftlen = packet.getSequence() - pospacket.getSequence();
        				long leftseq = pospacket.getSequence();
        				long rightlen = pospacket.getSequence() + pospacket.getLength() - 
        						packet.getSequence() + packet.getLength();
        				long rightseq = packet.getSequence() + packet.getLength();
        				
                    	PlaceholderTcpPacket lpacket = new PlaceholderTcpPacket(packet.getSourceIP(), 
                    			packet.getSourcePort(), packet.getDestinationIP(), packet.getDestinationPort(), 
                    			leftseq, (int) leftlen);
                    	PlaceholderTcpPacket rpacket = new PlaceholderTcpPacket(packet.getSourceIP(), 
                    			packet.getSourcePort(), packet.getDestinationIP(), packet.getDestinationPort(), 
                    			rightlen, (int) rightseq);
        				

        				if(lpacket.getLength() > 0){
        					this.setOrderedPacket(lpacket, type, index);
        					this.insertOrderedPacket(packet, type, index + 1);
        					if(rpacket.getLength() > 0){
        						this.insertOrderedPacket(rpacket, type, index + 2);
        					}
        				} else {
        					this.setOrderedPacket(packet, type, index);
        					this.insertOrderedPacket(rpacket, type, index + 1);
        				}
        			}
        			retval = true;
        			break;
    			}
    		}
    	}
    	return retval;
    }
    
    private List<Integer> getPacketIndexes(PacketType type){
    	return isRequest(type) ? reqIndexes : respIndexes ;
    }
    
    private void incPacketIndexes(int greaterthan, int inc){
    	for(int i = 0; i < reqIndexes.size(); i++){
    		if(reqIndexes.get(i) > greaterthan){
    			reqIndexes.set(i, reqIndexes.get(i) + inc);
    		}
    	}
    	for(int i = 0; i < respIndexes.size(); i++){
    		if(respIndexes.get(i) > greaterthan){
    			respIndexes.set(i, respIndexes.get(i) + inc);
    		}
    	}
    }
    
    private void setOrderedPacket(TcpPacket packet, PacketType type, int index){
    	rebuildData = true;
    	Integer indexObj = index;
    	orderedPackets.set(index, packet);
    	if(isRequest(type)){
    		if(!reqIndexes.contains(indexObj)){
    			reqIndexes.add(indexObj);
    		}
    		if(respIndexes.contains(indexObj)){
    			respIndexes.remove(indexObj);
    		}
    	} else {
    		if(!respIndexes.contains(indexObj)){
    			respIndexes.add(indexObj);
    		}
    		if(reqIndexes.contains(indexObj)){
    			reqIndexes.remove(indexObj);
    		}
    	}
    }
    
    private void insertOrderedPacket(TcpPacket packet, PacketType type, int index){
    	rebuildData = true;
    	orderedPackets.add(index, packet);
    	incPacketIndexes(index, 1);
    	if(isRequest(type)){
    		reqIndexes.add(index);
    	} else {
    		respIndexes.add(index);
    	}
    }
    
    private void addOrderedPacket(TcpPacket packet, PacketType type){
    	rebuildData = true;
    	orderedPackets.add(packet);
    	if(isRequest(type)){
    		reqIndexes.add(orderedPackets.size() - 1);
    	} else {
    		respIndexes.add(orderedPackets.size() - 1);
    	}
    }
    
    private long getLastOrderedSequence(PacketType type){
    	TcpPacket last = null;
    	if(isRequest(type)){
    		if(reqIndexes.size() > 0){
    			last = orderedPackets.get(reqIndexes.get(reqIndexes.size() - 1));
    		}
    	} else {
    		if(respIndexes.size() > 0){
    			last = orderedPackets.get(respIndexes.get(respIndexes.size() - 1));
    		}
    	}
    	if(last != null){
    		return last.getSequence();
    	}
    	
    	return -1;
    }
}

