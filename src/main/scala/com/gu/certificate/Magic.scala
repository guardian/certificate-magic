package com.gu.certificate

import java.io.File

import scalax.file.Path
import scalax.io.Resource


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

  def saveFile(content:String, domain:String, ext:String): File = {
    val path = Path.fromString(s"${homeDir.get}/.magic")
    path.createDirectory(createParents = true, failIfExists = false)
    val file = path / s"${safeDomainString(domain)}.$ext"
    file.write(content)
    file.fileOption.get
  }

  parser.parse(args, Config()) foreach {
    case Config("create", domain, profile, _, _) =>
      // create keypair
      val keyPair = BouncyCastle.createKeyPair()
      val privateKey = keyPair.getPrivate
      val pkPem = BouncyCastle.toPem(keyPair.getPrivate)
      // TODO: encrypt keypair to disk
      val pkFile = saveFile(pkPem, domain, "pk")
      println(s"Written PK to $pkFile")
      // create CSR
      val csr = BouncyCastle.createCsr(keyPair, domain)
      val csrPem = BouncyCastle.toPem(csr)
      println(s"CSR: $csrPem")
      // display/save CSR
      val csrFile = saveFile(csrPem, domain, "csr")
      println(s"Written CSR to $csrFile")
    case Config("install", _, profile, certificate, chain) =>
      // inspect certificate to discover domain
      // find and decrypt keypair
      // check certificate matches keypair? (or rely on AWS?)
      // build chain
      // upload to AWS
        // create temporary IAM credentials
        // do upload
        // delete temporary IAM credentials
  }
}
