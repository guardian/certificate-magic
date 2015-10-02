package com.gu.certificate

import java.io.StringWriter
import java.security.{KeyPair, KeyPairGenerator}

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x500.{X500Name, X500NameBuilder}
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import org.bouncycastle.util.io.pem.{PemObjectGenerator, PemWriter}


object BouncyCastle {
  def createKeyPair(): KeyPair = {
    val keyGen = KeyPairGenerator.getInstance("RSA")
    keyGen.initialize(2048)
    keyGen.generateKeyPair()
  }

  def createSubject(rdns: (ASN1ObjectIdentifier, String)*): X500Name = {
    val builder = new X500NameBuilder(BCStyle.INSTANCE)
    rdns.foreach{ case (id, value) => builder.addRDN(id, value)}
    builder.build()
  }

  def createSubject(domain: String): X500Name = {
    createSubject(
      BCStyle.C -> "GB",
      BCStyle.ST -> "London",
      BCStyle.L -> "London",
      BCStyle.O -> "Guardian News and Media",
      BCStyle.OU -> "The Guardian",
      BCStyle.EmailAddress -> "dnsmaster@guardian.co.uk",
      BCStyle.CN -> domain
    )
  }

  def createCsr(keyPair:KeyPair, domain:String): PKCS10CertificationRequest = {
    val subject = createSubject(domain)
    val builder = new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic)
    val csBuilder = new JcaContentSignerBuilder("SHA256withRSA")
    val signer = csBuilder.build(keyPair.getPrivate)
    builder.build(signer)
  }

  def toPem(obj:Object): String = {
    val textWriter = new StringWriter()
    val pemWriter = new JcaPEMWriter(textWriter)
    pemWriter.writeObject(obj)
    pemWriter.flush()
    textWriter.toString
  }
}
