package com.lastpass.saml;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.net.URLEncoder;

public class RequestGenerator
{
    public static void main(String... args) throws Exception
    {
        final String spMetadataPath = args[0];
        final String idpMetadataPath = args[1];
        final String privateKeyPath = args[2];

        final SAMLClient saml = SAMLClient.getInstance(spMetadataPath, idpMetadataPath, privateKeyPath);

        final String requestId = "id" + SAMLUtils.generateRequestId();
        final String authrequest = saml.generateAuthnRequest(requestId);

        final String encodedRequest = URLEncoder.encode(authrequest, "UTF-8");
        final String loginUrl = saml.getIdPConfig().getLoginUrl();

        final String url = String.format("%s?SAMLRequest=%s", loginUrl, encodedRequest);

        new ObjectMapper()
                .writerWithDefaultPrettyPrinter()
                .writeValue(System.out, url);
    }
}
