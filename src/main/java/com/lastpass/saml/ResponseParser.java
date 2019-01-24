package com.lastpass.saml;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.util.Arrays;

import static com.lastpass.saml.SAMLUtils.readBytes;

public class ResponseParser
{
    public static void main(String... args) throws Exception
    {
      final String spMetadataPath = args[0];
      final String idpMetadataPath = args[1];
      final String privateKeyPath = args[2];
      final String responsePath = args[3];
      final boolean sigErrorsAreFatal = Boolean.valueOf(args[4]);

      AttributeSet attrs;
      try
      {
        final String authnResponse = new String(readBytes(new File(responsePath)));
        final SAMLClient saml = SAMLClient.getInstance(spMetadataPath, idpMetadataPath, privateKeyPath);
        attrs = saml.validateResponse(authnResponse, sigErrorsAreFatal);
      }
      catch (Exception e)
      {
        attrs = new AttributeSet(null, null, Arrays.asList(e.getMessage()), null);
      }

      new ObjectMapper()
              .writerWithDefaultPrettyPrinter()
              .writeValue(System.out, attrs);
    }
}
