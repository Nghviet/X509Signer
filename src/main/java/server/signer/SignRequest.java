package server.signer;

import java.security.Signature;

public class SignRequest {
    public String csr;

    public SignRequest(String csr) {
        this.csr = csr;
    }
}
