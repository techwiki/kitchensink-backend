package org.jboss.quickstarts.kitchensink.controller;

import lombok.RequiredArgsConstructor;
import org.jboss.quickstarts.kitchensink.security.KeyPairService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/keys")
@RequiredArgsConstructor
public class KeyController {
    
    private final KeyPairService keyPairService;
    
    @GetMapping("/public")
    public PublicKeyResponse getPublicKey() {
        return new PublicKeyResponse(keyPairService.getPublicKeyBase64());
    }
}

record PublicKeyResponse(String publicKey) {} 