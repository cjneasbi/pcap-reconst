/*
 * Author: Manoj Bharadwaj
 */

package pcap.reconst.beans;

import org.apache.commons.lang3.StringUtils;
import pcap.reconst.compression.CompressionType;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class Headers {
    public static final String CONTENT_LENGTH = "Content-Length";
    public static final String CONTENT_ENCODING = "Content-Encoding";
    public static final String ACCEPT_ENCODING = "Accept-Encoding";
    public static final String GZIP = "gzip";
    public static final String DICT = "dict";
    public static final String DEFLATE = "deflate";

    private Map<String, String> headers;
    private CompressionType compressionType;

    public Headers() {
        headers = new HashMap<String, String>();
    }

    public void addHeader(String name, String value) {
        headers.put(name, value);
    }

    public Set<String> getNames() {
        return headers.keySet();
    }

    public String getValue(String name) {
        return headers.get(name);
    }

    public boolean hasHeader(String key) {
        return headers.keySet().contains(key);
    }

    public boolean checkIfExistsWithNonEmptyValue(String tag) {
        if (hasHeader(tag)) {
            String value = getValue(tag);
            return StringUtils.isNotEmpty(value);
        }
        return false;
    }

    public String getIfExistsWithNonEmptyValue(String tag) {
        if (hasHeader(tag)) {
            String value = getValue(tag);
            if (StringUtils.isNotEmpty(value)) {
                return value;
            }
        }
        return null;
    }

    @Override
    public String toString() {
        return headers.toString();
    }

    public int getContentLength() {
        String contentLength = getValue(CONTENT_LENGTH);
        if (StringUtils.isNumeric(contentLength)) {
            return Integer.parseInt(contentLength);
        }
        return 0;
    }

    public CompressionType getCompressionType() {
        String contentEncoding = getValue(Headers.CONTENT_ENCODING);
        if (StringUtils.isNotEmpty(contentEncoding) && CompressionType.isValid(contentEncoding)) {
            compressionType = CompressionType.valueOf(contentEncoding);
        }
        return compressionType;
    }
}
