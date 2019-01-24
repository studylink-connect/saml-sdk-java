/*
 * SAMLUtils - Utility functions
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 * Copyright (c) 2014 LastPass, Inc.
 */
package com.lastpass.saml;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

public class SAMLUtils
{
    private static final char[] hexes = "0123456789abcdef".toCharArray();

    private static String hexEncode(byte[] b)
    {
        char[] out = new char[b.length * 2];
        for (int i = 0; i < b.length; i++)
        {
            out[i*2] = hexes[(b[i] >> 4) & 0xf];
            out[i*2 + 1] = hexes[b[i] & 0xf];
        }
        return new String(out);
    }

    /**
     *  Generate a request ID suitable for passing to
     *  SAMLClient.createAuthnRequest.
     */
    public static String generateRequestId()
    {
        /* compute a random 256-bit string and hex-encode it */
        SecureRandom sr = new SecureRandom();
        byte[] bytes = new byte[32];
        sr.nextBytes(bytes);
        return "_" + hexEncode(bytes);
    }

    public static byte[] readBytes(File file) throws IOException
    {
        // was implemented tediously prior to Java 7, now a simple wrapper
        return Files.readAllBytes(file.toPath());
    }

    static RSAPrivateKey getRsaPrivateKey(String path) throws SAMLException
    {
      try
      {
        final KeySpec spec = new PKCS8EncodedKeySpec(readBytes(new File(path)));
        return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(spec);
      }
      catch (InvalidKeySpecException e)
      {
        throw new SAMLException(e);
      }
      catch (NoSuchAlgorithmException e)
      {
        throw new SAMLException(e);
      }
      catch (IOException e)
      {
        throw new SAMLException(e);
      }
    }
}
