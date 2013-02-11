/*
 * Author: Manoj Bharadwaj
 */

package pcap.reconst.compression;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.ByteArrayOutputStream;
import java.util.zip.Deflater;

public class Deflate implements Zip {
	private static Log log = LogFactory.getLog(Deflate.class);

    private byte[] input;
    private Dict dict;

    public Deflate(byte[] input, Dict dict) {
        this.input = input;
        this.dict = dict;
    }

    public byte[] zip() {
        Deflater deflater = new Deflater();

        if (dict != null) {
            deflater.setDictionary(dict.getDict());
        } else {
        	if(log.isDebugEnabled()){
        		log.debug("no dictionary");
        	}
        }

        deflater.setInput(input);
        deflater.finish();
        byte[] output = new byte[100];
        ByteArrayOutputStream bo = new ByteArrayOutputStream();

        int compressedDataLength;
        while (true) {
            compressedDataLength = deflater.deflate(output, 0, output.length);
            if (compressedDataLength == 0)
                break;
            bo.write(output, 0, compressedDataLength);
            if (compressedDataLength != output.length)
                break;

        }
        deflater.end();
        return bo.toByteArray();
    }
}