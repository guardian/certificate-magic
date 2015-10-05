package com.gu.certificate

import java.io.{StringReader, ByteArrayInputStream, InputStreamReader, StringWriter}
import java.security.{KeyPair, KeyPairGenerator}

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x500.{X500Name, X500NameBuilder}
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.{AuthorityInformationAccess, Extension}
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.openssl.{PEMKeyPair, PEMParser}
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder

import scalax.io.Resource

trait BouncyCastle {

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

  def readCertificate(pem: String): Option[X509CertificateHolder] = {
    val parser = new PEMParser(new StringReader(pem))
    val pemObject = Option(parser.readObject())
    pemObject match {
      case Some(cert:X509CertificateHolder) => Some(cert)
      case _ => None
    }
  }

  def getRDNValue(certificate: X509CertificateHolder, rdn:ASN1ObjectIdentifier) =
    certificate.getSubject.getRDNs(rdn).toList.head.getFirst.getValue.toString
  
  def getCommonName(certificate: X509CertificateHolder) = getRDNValue(certificate, BCStyle.CN)

  def readKeyPair(pem: String) = {
    val parser = new PEMParser(new StringReader(pem))
    val pemObject = Option(parser.readObject())
    pemObject match {
      case Some(kp:PEMKeyPair) => Some(kp)
      case _ => None
    }
  }

  def getChainFromCertificate(certificate: X509CertificateHolder): List[X509CertificateHolder] = {
    def getChainFromCertificateRec(certificate: X509CertificateHolder, acc: List[X509CertificateHolder]): List[X509CertificateHolder] = {
      val chain = certificate :: acc
      getAiaCertificate(certificate) match {
        case None => chain
        case Some(authorityCertificate) =>
          getChainFromCertificateRec(authorityCertificate, chain)
      }
    }

    getAiaCertificate(certificate).map(getChainFromCertificateRec(_, Nil).reverse).getOrElse(Nil)
  }

  def getAiaCertificate(certificate: X509CertificateHolder) = getAiaUrl(certificate).map(getCertificate)

  def getCertificate(url: String) = {
    System.err.println(s"fetching certificate from: $url")
    new X509CertificateHolder(Resource.fromURL(url).byteArray)
  }

  def getAiaUrl(certificate: X509CertificateHolder): Option[String] = {
    val accessLocationIdentifier = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.2")
    Option(certificate.getExtension(Extension.authorityInfoAccess).getParsedValue)
      .toList
      .map(AuthorityInformationAccess.getInstance)
      .flatMap(_.getAccessDescriptions)
      .find(_.getAccessMethod == accessLocationIdentifier)
      .map(_.getAccessLocation.getName.toASN1Primitive.toString)
  }

}
