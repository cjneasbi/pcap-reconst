/*
 * Author(s): Manoj Bharadwaj, Chris Neasbitt
 */

package pcap.reconst;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import pcap.reconst.beans.Headers;
import pcap.reconst.compression.CompressionType;

import java.io.*;
import java.net.HttpURLConnection;

public class Utils {
	private static Log log = LogFactory.getLog(Utils.class);

    public static byte[] getByteArray(String fileName) {
        return getByteArray(new File(fileName));
    }

    public static byte[] getByteArray(File file) {
        try {
            return getByteArray(new FileInputStream(file));
        } catch (FileNotFoundException e) {
            return null;
        }
    }

    public static byte[] getByteArray(InputStream inputStream) {
        byte[] bytes = null;
        int totalLength = 0;
        byte[] tempBytes = new byte[1024];
        try {
            int length;
            while ((length = inputStream.read(tempBytes, 0, tempBytes.length)) != -1) {
                totalLength += length;
                if (totalLength - length > 0) {
                    byte[] newlyReadBytes = new byte[totalLength];
                    System.arraycopy(bytes, 0, newlyReadBytes, 0, totalLength - length);
                    bytes = newlyReadBytes;
                } else {
                    bytes = new byte[length];
                }
                System.arraycopy(tempBytes, 0, bytes, totalLength - length, length);
            }
        } catch (IOException e1) {
            return null;
        }
        return bytes;
    }

    public static Headers getHttpHeaders(HttpURLConnection con) {
        Headers headers = new Headers();
        for (int i = 0; ; i++) {
            String headerName = con.getHeaderFieldKey(i);
            String headerValue = con.getHeaderField(i);

            if (headerName == null && headerValue == null) {
                break;
            }
            headers.addHeader(headerName, headerValue);
        }
        return headers;
    }

    public static void prettyPrintHex(byte[] data) {
        int i = 0;
        int j = 0;
        int lineAddr = 0;
        if (data.length == 0) {
            return;
        }

        StringBuilder stringBuilder = new StringBuilder();
        //Loop through every input byte
        String hexline = "";
        String asciiline = "";
        for (i = 0, lineAddr = 0; i < data.length; i++, lineAddr++) {
            //Print the line numbers at the beginning of the line
            if ((i % 16) == 0) {
                if (i != 0) {
                    stringBuilder.append(hexline);
                    stringBuilder.append("\t...\t");
                    stringBuilder.append(asciiline + "\n");
                }
                asciiline = "";
                hexline = String.format("%#06x ", lineAddr);
            }
            hexline = hexline.concat(String.format("%#04x ", data[i]));
            if (data[i] > 31 && data[i] < 127) {
                asciiline = asciiline.concat(String.valueOf((char) data[i]));
            } else {
                asciiline = asciiline.concat(".");
            }
        }
        // Handle the ascii for the final line, which may not be completely filled.
        if (i % 16 > 0) {
            for (j = 0; j < 16 - (i % 16); j++) {
                hexline = hexline.concat("     ");
            }
            stringBuilder.append(hexline);
            stringBuilder.append("\t...\t");
            stringBuilder.append(asciiline);
        }
        if(log.isDebugEnabled()){
        	log.debug(stringBuilder.toString());
        }
    }

    public static byte[] intToByteArray(int value) {
        return new byte[]{
                (byte) (value >>> 24),
                (byte) (value >>> 16),
                (byte) (value >>> 8),
                (byte) value};
    }

    public static boolean isCompressed(CompressionType compressionType) {
        boolean isCompressed = false;
        if (compressionType != null) {
            isCompressed = true;
        }
        return isCompressed;
    }

}
