/*
 * Author: Manoj Bharadwaj
 */

package pcap.reconst.output;

import pcap.reconst.beans.InputData;

public class HttpOutput {
    private byte[] payload;
    private InputData request;
    private InputData response;

    public HttpOutput(byte[] payload, InputData request, InputData response) {
        this.payload = payload;
        this.request = request;
        this.response = response;
    }

    public byte[] getPayload() {
        return payload;
    }

    public InputData getRequest() {
        return request;
    }

    public InputData getResponse() {
        return response;
    }
}
