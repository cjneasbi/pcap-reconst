package pcap.reconst.http.datamodel;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import org.apache.http.impl.io.AbstractSessionInputBuffer;
import org.apache.http.params.BasicHttpParams;

public class MessageStringInputBuffer extends AbstractSessionInputBuffer {

	public MessageStringInputBuffer(String message){
		init(new ByteArrayInputStream(message.getBytes()), 10, new BasicHttpParams());
	}
	
	@Override
	public boolean isDataAvailable(int arg0) throws IOException {
		throw new UnsupportedOperationException();
	}



}
