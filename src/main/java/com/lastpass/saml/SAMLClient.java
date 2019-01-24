/*
 * SAMLClient - Main interface module for service providers.
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
 * Copyright (c) 2014-2015 LastPass, Inc.
 */
package com.lastpass.saml;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;

import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.Attribute;

import org.opensaml.saml2.encryption.Decrypter;

import org.opensaml.common.SAMLObjectBuilder;

import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.validation.ValidationException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.XMLObject;

import org.joda.time.DateTime;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSSerializer;
import org.xml.sax.InputSource;

import java.io.*;

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.zip.Deflater;

import javax.xml.bind.DatatypeConverter;

public class SAMLClient
{
  private String idpMetadataPath;
  private String spMetadataPath;
  private String baseDir;
  private String privateKeyPath;

  private SPConfig spConfig;
  private IdPConfig idpConfig;
  private SignatureValidator sigValidator;
  private BasicParserPool parsers;

  /* do date comparisons +/- this many seconds */
  private static final int slack = (int) TimeUnit.MINUTES.toSeconds(5);

  /**
   * Create a new SAMLClient, using the IdPConfig for
   * endpoints and validation.
   */
  public SAMLClient(SPConfig spConfig, IdPConfig idpConfig)
  {
    this.spConfig = spConfig;
    this.idpConfig = idpConfig;

    BasicCredential cred = new BasicCredential();
    cred.setEntityId(idpConfig.getEntityId());
    cred.setPublicKey(idpConfig.getCert().getPublicKey());

    sigValidator = new SignatureValidator(cred);

    // create xml parsers
    parsers = new BasicParserPool();
    parsers.setNamespaceAware(true);
  }

  public SAMLClient(File spConfigFile, File idpConfigFile, String privateKeyPath, String baseDir)
          throws SAMLException
  {
    this(new SPConfig(spConfigFile), new IdPConfig(idpConfigFile));
    this.privateKeyPath = privateKeyPath;
    this.baseDir = baseDir;
    this.idpMetadataPath = idpConfigFile.getAbsolutePath();
    this.spMetadataPath = spConfigFile.getAbsolutePath();
  }

  /**
   * Get the configured IdpConfig.
   *
   * @return the IdPConfig associated with this client
   */
  public IdPConfig getIdPConfig()
  {
    return idpConfig;
  }

  /**
   * Get the configured SPConfig.
   *
   * @return the SPConfig associated with this client
   */
  public SPConfig getSPConfig()
  {
    return spConfig;
  }

    private Response parseResponse(String authnResponse)
        throws SAMLException
    {
        try {
            Document doc = parsers.getBuilder()
                .parse(new InputSource(new StringReader(authnResponse)));

      Element root = doc.getDocumentElement();
      return (Response) Configuration.getUnmarshallerFactory()
        .getUnmarshaller(root)
        .unmarshall(root);
    }
    catch (org.opensaml.xml.parse.XMLParserException e)
    {
      throw new SAMLException(e);
    }
    catch (org.opensaml.xml.io.UnmarshallingException e)
    {
      throw new SAMLException(e);
    }
    catch (org.xml.sax.SAXException e)
    {
      throw new SAMLException(e);
    }
    catch (java.io.IOException e)
    {
      throw new SAMLException(e);
    }
  }

  /**
   * Decrypt an assertion using the privkey stored in SPConfig.
   */
  private Assertion decrypt(EncryptedAssertion encrypted)
    throws DecryptionException
  {
    if (spConfig.getPrivateKey() == null)
      throw new DecryptionException("Encrypted assertion found but no SP key available");
    BasicCredential cred = new BasicCredential();
    cred.setPrivateKey(spConfig.getPrivateKey());
    StaticKeyInfoCredentialResolver resolver =
      new StaticKeyInfoCredentialResolver(cred);
    Decrypter decrypter =
      new Decrypter(null, resolver, new InlineEncryptedKeyResolver());
    decrypter.setRootInNewDocument(true);

    return decrypter.decrypt(encrypted);
  }

  /**
   * Retrieve all supplied assertions, decrypting any encrypted
   * assertions if necessary.
   */
  private List<Assertion> getAssertions(Response response)
    throws DecryptionException
  {
    List<Assertion> assertions = new ArrayList<Assertion>();
    assertions.addAll(response.getAssertions());

    for (EncryptedAssertion e : response.getEncryptedAssertions())
    {
      final Assertion assertion = decrypt(e);
      assertions.add(assertion);
    }

    return assertions;
  }

  private List<String> validate(Response response, boolean signatureErrorsAreFatal)
    throws ValidationException
  {
    List<String> warnings = new ArrayList<>();

    // response signature must match IdP's key, if present
    Signature sig = response.getSignature();
    if (sig != null)
    {
      try
      {
        sigValidator.validate(sig);
      }
      catch (ValidationException ve)
      {
        if (signatureErrorsAreFatal)
        {
          throw ve;
        }

        warnings.add("invalid response signature: " + ve.getMessage());
      }
    }
    else {
      warnings.add("unsigned response");
    }

    // response must be successful
    if (response.getStatus() == null ||
      response.getStatus().getStatusCode() == null ||
      !(StatusCode.SUCCESS_URI
        .equals(response.getStatus().getStatusCode().getValue())))
    {
      throw new ValidationException(
        "Response has an unsuccessful status code");
    }

    // response destination must match ACS
    if (!spConfig.getAcs().equals(response.getDestination()))
      throw new ValidationException(
        "Response is destined for a different endpoint");

    DateTime now = DateTime.now();

    // issue instant must be within a day
    DateTime issueInstant = response.getIssueInstant();

        if (issueInstant != null) {
            if (issueInstant.isBefore(now.minusSeconds(slack)))
                throw new ValidationException(
                    "Response IssueInstant is too far in the past");

        if (issueInstant.isAfter(now.plusSeconds(slack)))
          throw new ValidationException(
            "Response IssueInstant is too far in the future");
    }

    List<Assertion> assertions = null;
    try
    {
      assertions = getAssertions(response);
    }
    catch (DecryptionException e)
    {
      throw new ValidationException(e);
    }

    for (Assertion assertion : assertions)
    {

      // Assertion must be signed correctly
      if (!assertion.isSigned())
      {
        if (signatureErrorsAreFatal)
        {
          throw new ValidationException("Assertion must be signed");
        }
        else
        {
          warnings.add("Assertion should be signed");
        }
      }

      sig = assertion.getSignature();
      try
      {
        sigValidator.validate(sig);
      }
      catch (ValidationException ve)
      {
        if (signatureErrorsAreFatal)
        {
          throw ve;
        }

        warnings.add("invalid assertion signature: " + ve.getMessage());
      }

      // Assertion must contain an authnstatement
      // with an unexpired session
      if (assertion.getAuthnStatements().isEmpty())
      {
        throw new ValidationException(
          "Assertion should contain an AuthnStatement");
      }
      for (AuthnStatement as : assertion.getAuthnStatements())
      {
        DateTime sessionTime = as.getSessionNotOnOrAfter();
        if (sessionTime != null)
        {
          DateTime exp = sessionTime.plusSeconds(slack);
          if (exp != null &&
            (now.isEqual(exp) || now.isAfter(exp)))
            throw new ValidationException(
              "AuthnStatement has expired");
        }
      }

      if (assertion.getConditions() == null)
      {
        throw new ValidationException(
          "Assertion should contain conditions");
      }

      // Assertion IssueInstant must be within a day
      DateTime instant = assertion.getIssueInstant();
      if (instant != null)
      {
        if (instant.isBefore(now.minusSeconds(slack)))
          throw new ValidationException(
            "Response IssueInstant is in the past");

        if (instant.isAfter(now.plusSeconds(slack)))
          throw new ValidationException(
            "Response IssueInstant is in the future");
      }

      // Conditions must be met by current time
      Conditions conditions = assertion.getConditions();
      DateTime notBefore = conditions.getNotBefore();
      DateTime notOnOrAfter = conditions.getNotOnOrAfter();

      if (notBefore == null || notOnOrAfter == null)
        throw new ValidationException(
          "Assertion conditions must have limits");

      notBefore = notBefore.minusSeconds(slack);
      notOnOrAfter = notOnOrAfter.plusSeconds(slack);

      if (now.isBefore(notBefore))
        throw new ValidationException(
          "Assertion conditions is in the future");

      if (now.isEqual(notOnOrAfter) || now.isAfter(notOnOrAfter))
        throw new ValidationException(
          "Assertion conditions is in the past");

      // If subjectConfirmationData is included, it must
      // have a recipient that matches ACS, with a valid
      // NotOnOrAfter
      Subject subject = assertion.getSubject();
      if (subject != null &&
        !subject.getSubjectConfirmations().isEmpty())
      {
        boolean foundRecipient = false;
        for (SubjectConfirmation sc : subject.getSubjectConfirmations())
        {
          if (sc.getSubjectConfirmationData() == null)
            continue;

          SubjectConfirmationData scd = sc.getSubjectConfirmationData();
          if (scd.getNotOnOrAfter() != null)
          {
            DateTime chkdate = scd.getNotOnOrAfter().plusSeconds(slack);
            if (now.isEqual(chkdate) || now.isAfter(chkdate))
            {
              throw new ValidationException(
                "SubjectConfirmationData is in the past");
            }
          }

          if (spConfig.getAcs().equals(scd.getRecipient()))
            foundRecipient = true;
        }

        if (!foundRecipient)
          throw new ValidationException(
            "No SubjectConfirmationData found for ACS");
      }

      // audience must include intended SP issuer
      if (conditions.getAudienceRestrictions().isEmpty())
        throw new ValidationException(
          "Assertion conditions must have audience restrictions");

      // only one audience restriction supported: we can only
      // check against the single SP.
      if (conditions.getAudienceRestrictions().size() > 1)
        throw new ValidationException(
          "Assertion contains multiple audience restrictions");

      AudienceRestriction ar = conditions.getAudienceRestrictions()
        .get(0);

      // at least one of the audiences must match our SP
      boolean foundSP = false;
      for (Audience a : ar.getAudiences())
      {
        if (spConfig.getEntityId().equals(a.getAudienceURI()))
          foundSP = true;
      }
      if (!foundSP)
        throw new ValidationException(
          "Assertion audience does not include issuer");
    }

    return warnings;
  }

  @SuppressWarnings("unchecked")
  private String createAuthnRequest(String requestId)
    throws SAMLException
  {
    XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

    SAMLObjectBuilder<AuthnRequest> builder =
      (SAMLObjectBuilder<AuthnRequest>) builderFactory
        .getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);

    SAMLObjectBuilder<Issuer> issuerBuilder =
      (SAMLObjectBuilder<Issuer>) builderFactory
        .getBuilder(Issuer.DEFAULT_ELEMENT_NAME);

    AuthnRequest request = builder.buildObject();
    request.setAssertionConsumerServiceURL(spConfig.getAcs().toString());
    request.setDestination(idpConfig.getLoginUrl().toString());
    request.setIssueInstant(new DateTime());
    request.setID(requestId);

    Issuer issuer = issuerBuilder.buildObject();
    issuer.setValue(spConfig.getEntityId());
    request.setIssuer(issuer);

    try
    {
      // samlobject to xml dom object
      Element elem = Configuration.getMarshallerFactory()
        .getMarshaller(request)
        .marshall(request);

      // and to a string...
      Document document = elem.getOwnerDocument();
      DOMImplementationLS domImplLS = (DOMImplementationLS) document
        .getImplementation();
      LSSerializer serializer = domImplLS.createLSSerializer();
      serializer.getDomConfig().setParameter("xml-declaration", false);
      return serializer.writeToString(elem);
    }
    catch (MarshallingException e)
    {
      throw new SAMLException(e);
    }
  }

  private byte[] deflate(byte[] input)
    throws IOException
  {
    // deflate and base-64 encode it
    Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
    deflater.setInput(input);
    deflater.finish();

    byte[] tmp = new byte[8192];
    int count;

    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    while (!deflater.finished())
    {
      count = deflater.deflate(tmp);
      bos.write(tmp, 0, count);
    }
    bos.close();
    deflater.end();

    return bos.toByteArray();
  }

  /**
   * Create a new AuthnRequest suitable for sending to an HTTPRedirect
   * binding endpoint on the IdP.  The SPConfig will be used to fill
   * in the ACS and issuer, and the IdP will be used to set the
   * destination.
   *
   * @return a deflated, base64-encoded AuthnRequest
   */
  public String generateAuthnRequest(String requestId)
    throws SAMLException
  {
    String request = createAuthnRequest(requestId);

    try
    {
      byte[] compressed = deflate(request.getBytes("UTF-8"));
      return DatatypeConverter.printBase64Binary(compressed);
    }
    catch (UnsupportedEncodingException e)
    {
      throw new SAMLException("Apparently your platform lacks UTF-8.  That's too bad.", e);
    }
    catch (IOException e)
    {
      throw new SAMLException("Unable to compress the AuthnRequest", e);
    }
  }

  public AttributeSet validateResponse(String authnResponse, boolean signatureErrorsAreFatal)
    throws SAMLException
  {
    final List<String> errors = new ArrayList<>();
    final List<String> warnings = new ArrayList<>();

    byte[] decoded = DatatypeConverter.parseBase64Binary(authnResponse);
    try
    {
      authnResponse = new String(decoded, "UTF-8");
    }
    catch (UnsupportedEncodingException e)
    {
      throw new SAMLException("Apparently your platform lacks UTF-8.  That's too bad.", e);
    }

    Response response = parseResponse(authnResponse);

    try
    {
      warnings.addAll(validate(response, signatureErrorsAreFatal));
    }
    catch (ValidationException e)
    {
      errors.add("response not valid: " + e.getMessage());
    }

    List<Assertion> assertions = null;
    try
    {
      assertions = getAssertions(response);
    }
    catch (DecryptionException e)
    {
      errors.add("unable to decrypt assertion: " + e.getMessage());
      return new AttributeSet(null, null, errors, warnings);
    }

    if (assertions.isEmpty())
    {
      errors.add("Response did not contain any assertions.");
      return new AttributeSet(null, null, errors, warnings);
    }

    // we only look at first assertion
    if (assertions.size() > 1)
    {
      errors.add("Response should have a single assertion.");
    }

    final Assertion assertion = assertions.get(0);
    final Subject subject = assertion.getSubject();

    if (subject == null)
    {
      errors.add("No subject contained in the assertion.");
    }

    String nameId = null;
    if (subject.getNameID() != null)
    {
      nameId = subject.getNameID().getValue();
    }

    final HashMap<String, List<String>> attributes =
            new HashMap<String, List<String>>();

    for (AttributeStatement atbs : assertion.getAttributeStatements())
    {
      for (Attribute atb : atbs.getAttributes())
      {
        String name = atb.getName();
        List<String> values = new ArrayList<String>();
        for (XMLObject obj : atb.getAttributeValues())
        {
          values.add(obj.getDOM().getTextContent());
        }
        attributes.put(name, values);
      }
    }

    return new AttributeSet(nameId, attributes,
            errors.isEmpty() ? null : errors,
            warnings.isEmpty() ? null : warnings);
  }

  public static SAMLClient getInstance(String spMetadataPath,
                                       String idpMetadataPath,
                                       String privateKeyPath)
          throws ConfigurationException, SAMLException
  {
    DefaultBootstrap.bootstrap();

    final SPConfig spConfig = new SPConfig(new File(spMetadataPath));
    spConfig.setPrivateKey(SAMLUtils.getRsaPrivateKey(privateKeyPath));
    final IdPConfig idpConfig = new IdPConfig(new File(idpMetadataPath));
    return new SAMLClient(spConfig, idpConfig);
  }

}
