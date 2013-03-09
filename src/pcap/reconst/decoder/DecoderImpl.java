/*
 * Author(s): Manoj Bharadwaj, Chris Neasbitt
 */

package pcap.reconst.decoder;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.util.EntityUtils;

import pcap.reconst.compression.CompressionType;
import pcap.reconst.compression.GzipZlibUtils;

public class DecoderImpl implements Decoder {

	private static Log log = LogFactory.getLog(DecoderImpl.class);

	public HttpEntity decodeEntity(HttpEntity ent) throws Exception {
		if (log.isDebugEnabled()) {
			log.debug("length is [" + ent.getContentLength() + "], data is ["
					+ EntityUtils.toString(ent) + "]");
		}
		
		byte[] decodeddata = null;
		CompressionType compressionType = this.getCompressionType(ent);
		if (compressionType != null) {
			decodeddata = GzipZlibUtils.uncompress(compressionType,
					convertInputStream(ent.getContent()));
			if (log.isDebugEnabled()) {
				log.debug("after gunzip: length is ["
						+ decodeddata.length + "], data is ["
						+ new String(decodeddata) + "]");
			}
		}
		if(decodeddata != null){
			return new ByteArrayEntity(decodeddata, ContentType.get(ent));
		} else {
			return null;
		}
	}
	
	private byte[] convertInputStream(InputStream is) throws IOException{
		List<Byte> bytes = new ArrayList<Byte>();
		int curbyte = 0;
		while((curbyte = is.read()) != -1){
			bytes.add((byte)curbyte);
		}
		return ArrayUtils.toPrimitive(bytes.toArray(new Byte[bytes.size()]));
	}
	
	private CompressionType getCompressionType(HttpEntity ent) {
		String contentEncoding = ent.getContentEncoding().getValue();
		CompressionType compressionType = null;
		if (StringUtils.isNotEmpty(contentEncoding)
				&& CompressionType.isValid(contentEncoding)) {
			compressionType = CompressionType.valueOf(contentEncoding);
		}
		return compressionType;
	}
}
