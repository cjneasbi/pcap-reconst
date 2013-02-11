/*
 * Author(s): Manoj Bharadwaj, Chris Neasbitt
 */

package pcap.reconst.output;

import pcap.reconst.beans.DecodedData;

public class HttpDecodedOutput extends HttpOutput {
    private DecodedData decodedResponse;

    public HttpDecodedOutput(HttpOutput httpOutput) {
        super(httpOutput.getPayload(), httpOutput.getRequest(), httpOutput.getResponse());
    }

    public DecodedData getDecodedResponse() {
        return decodedResponse;
    }

    public void setDecodedResponse(DecodedData decodedResponse) {
        this.decodedResponse = decodedResponse;
    }
}