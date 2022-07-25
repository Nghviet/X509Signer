package server.signer;


import org.springframework.context.annotation.Import;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import server.signer.Signer;

import javax.servlet.http.HttpServletRequest;

import java.util.LinkedHashMap;

@RestController
public class RESTController {
    @GetMapping("/API/signer")
    public String alive() {
        return "SIGNER AVAILABLE";
    }

    @PostMapping("/API/signer/sign")
    public String sign(HttpServletRequest request, @RequestBody Object object) throws Exception {
        LinkedHashMap<String, String> map = (LinkedHashMap<String,String>) object;
        String user = request.getHeader("user_id");
        if(request.getHeader("home_id") != null && !request.getHeader("home_id").equals("")) user += "/" + request.getHeader("home_id");
        return Signer.getInstance().sign(map.get("csr"), user);
    }

    @GetMapping("/API/signer/CA")
    public String caFile(HttpServletRequest request) throws Exception {
        return Signer.getInstance().getCA();
    }
}
