package com.gu.certificate

import java.io.File
import java.nio.ByteBuffer

import scalax.file.Path

object Magic extends App {
  case class Config(mode:String="", domain:String="", awsProfile:Option[String]=None, certificate:Option[File]=None, chain:Option[File]=None)

  val parser = new scopt.OptionParser[Config]("magic") {
    head("certificate magic", "1.0")
    opt[String]('p', "profile") optional() action { (x, c) => c.copy(awsProfile = Some(x)) }
    cmd("create") action { (_, c) =>
      c.copy(mode = "create") } text "create a new keypair and certificate signing request (CSR)" children(
        opt[String]('d', "domain") required() action { (x, c) => c.copy(domain = x) }
      )
    cmd("install") action { (_, c) =>
      c.copy(mode = "install") } text "install a certificate" children(
      opt[File]("certificate") required() action { (x, c) =>
        c.copy(certificate = Some(x)) } text "provided certificate",
      opt[File]("chain") optional() action { (x, c) =>
        c.copy(chain = Some(x)) } text "provided certificate chain (will try to build it if not provided)"
      )
  }

  def safeDomainString(domain: String): String = {
    domain.replace("*", "star")
  }

  def homeDir = Option(System.getProperty("user.home"))

  def getFile(domain:String, ext:String) = {
    val path = Path.fromString(s"${homeDir.get}/.magic")
    path.createDirectory(createParents = true, failIfExists = false)
    path / s"${safeDomainString(domain)}.$ext"
  }

  def saveFile(content:String, domain:String, ext:String): File = {
    val file = getFile(domain, ext)
    file.write(content)
    file.fileOption.get
  }

  def saveFile(content:ByteBuffer, domain:String, ext:String): File = {
    val file = getFile(domain, ext)
    file.write(content)
    file.fileOption.get
  }

  def readBytes(domain:String, ext:String): ByteBuffer = {
    val file = getFile(domain, ext)
    ByteBuffer.wrap(file.byteArray)
  }


  parser.parse(args, Config()) foreach {
    case Config("create", domain, profile, _, _) =>
      // create keypair
      val keyPair = BouncyCastle.createKeyPair()
      val pkPem = BouncyCastle.toPem(keyPair.getPrivate)

      // encrypt private key with KMS
      val aws = new AwsEncryption()
      val keyId = aws.getCertificateMagicKey
      val ciphertext = aws.encrypt(keyId, pkPem, domain)
      val pkEncFile = saveFile(ciphertext, domain, "pkenc")

      // create CSR
      val csrPem= BouncyCastle.toPem(BouncyCastle.createCsr(keyPair, domain))
      // display/save CSR
      val csrFile = saveFile(csrPem, domain, "csr")

      // give details to user
      println(s"Written encrypted PK to $pkEncFile")
      println(s"Written CSR to $csrFile")

    case Config("install", _, profile, certificate, chain) =>
      val aws = new AwsEncryption()
      // inspect certificate to discover domain
      val domain = ???
      // find and decrypt private key
      val readPkEncFile = readBytes(domain, "pkenc")
      val decryptedPem = aws.decrypt(readPkEncFile, domain)
      println(s"decrypted: $decryptedPem")

      // check certificate matches keypair? (or rely on AWS?)
      // build chain
      // upload to AWS
        // create temporary IAM credentials
        // do upload
        // delete temporary IAM credentials
  }
}
