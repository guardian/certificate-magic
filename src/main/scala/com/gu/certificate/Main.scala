package com.gu.certificate

import java.io.File


object Main extends App {
  case class Config(mode:String="", domain:String="", awsProfile:Option[String]=None, certificate:Option[File]=None, chain:Option[File]=None, force:Boolean=false, awsRegionName:Option[String]=None)

  val parser = new scopt.OptionParser[Config]("magic") {
    head("certificate magic", "1.0")
    opt[String]('p', "profile") optional() action { (x, c) => c.copy(awsProfile = Some(x)) }
    opt[String]('r', "region") optional() action { (x, c) => c.copy(awsRegionName = Some(x)) }
    cmd("create") action { (_, c) =>
      c.copy(mode = "create") } text "create a new keypair and certificate signing request (CSR)" children(
        opt[String]('d', "domain") required() action { (x, c) => c.copy(domain = x) },
        opt[Unit]('f', "force") optional() action { (_, c) => c.copy(force = true) }
      )
    cmd("install") action { (_, c) =>
      c.copy(mode = "install") } text "install a certificate" children(
      opt[File]("certificate") required() action { (x, c) =>
        c.copy(certificate = Some(x)) } text "provided certificate",
      opt[File]("chain") optional() action { (x, c) =>
        c.copy(chain = Some(x)) } text "provided certificate chain (will try to build it if not provided)"
      )
    cmd("list") action { (_, c) => c.copy(mode = "list") }
  }

  parser.parse(args, Config()) foreach {
    case Config("create", domain, profile, _, _, force, regionNameOpt) =>
      Magic.create(domain, profile, force, regionNameOpt)

    case Config("install", _, profile, Some(certificateFile), chainFile, _, regionNameOpt) =>
      Magic.install(profile, certificateFile, chainFile, regionNameOpt)

    case Config("list", _, _, _, _, _, _) =>
      ???
  }

}
