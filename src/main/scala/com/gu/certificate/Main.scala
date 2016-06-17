package com.gu.certificate

import java.io.File


object Main extends App {
  case class Config(mode:String="", domain:String="", awsProfile:Option[String]=None, certificate:Option[File]=None, chain:Option[File]=None, force:Boolean=false, awsRegionName:Option[String]=None, installProfile:Option[String] = None, path:Option[String] = None, awsService:Option[String] = Some("iam"))

  val parser = new scopt.OptionParser[Config]("cert-magic") {
    head("certificate magic", "1.0-SNAPSHOT")
    note(
      s"""cert-magic is a tool to help create https certificates and install them in AWS.
        |
        |${Console.BOLD}DESCRIPTION${Console.RESET}
        |  To set up a new certificate in AWS perform the following steps
        |
        |  1. run the create command to generate a CSR and encrypted private key
        |  2. (IRL) get the certificate issued using your provider
        |  3. run the install command with the certificate you get back from (2.)
        |  4. (IRL) set up the certificate for your application and test it is working
        |  5. run tidy to delete the temporary files
        |
        |${Console.BOLD}EXAMPLES${Console.RESET}
        |  Create a new CSR for your domain, using your configured AWS profile
        |    cert-magic create -d www.example.com -p my-aws-profile
        |  Create a CSR for a wildcard domain, specifying the region
        |    cert-magic create -d *.example.com -p my-profile -r eu-west-1
        |  Install a certificate into AWS
        |    cert-magic install --certificate <path to cert> --chain <path to chain/bundle> -p aws-profile
        |  Install a certificate into a second (different) AWS account
        |    cert-magic install --certificate <path to cert> --chain <path to chain/bundle> -p aws-profile --installProfile different-aws-profile
        |  Install a certificate into a second (not IAM) AWS service (e.g. API GateWay)
        |    cert-magic install --certificate <path to cert> --chain <path to chain/bundle> -p aws-profile --service apigateway
        |  Delete the files associated with a domain (to clear up after installation)
        |    cert-magic tidy -d www.example.com
        |""".stripMargin)
    cmd("create") action { (_, c) =>
      c.copy(mode = "create") } text "create a new keypair and certificate signing request (CSR)" children(
        opt[String]('d', "domain") required() action { (x, c) =>
          c.copy(domain = x)
        } text "The domain for the certificate (e.g. www.example.com or *.mydomain.co.uk)",
      opt[String]('p', "profile") optional() action { (x, c) =>
        c.copy(awsProfile = Some(x))
      } text "(optionally), AWS profile to provide credentials",
      opt[String]('r', "region") optional() action { (x, c) =>
        c.copy(awsRegionName = Some(x))
      } text "(optionally), AWS region to use - you may have already configured the region in your AWS profile",
        opt[Unit]('f', "force") optional() action { (_, c) =>
          c.copy(force = true)
        } text "force the creation to overwrite an existing private key for this domain\n"
      )
    cmd("install") action { (_, c) =>
      c.copy(mode = "install") } text "install a certificate into your AWS account" children(
      opt[File]("certificate") required() action { (x, c) =>
        c.copy(certificate = Some(x)) } text "provided certificate/crt file" valueName "<certificate file>",
      opt[File]("chain") optional() action { (x, c) =>
        c.copy(chain = Some(x)) } text "provided certificate chain/bundle file (will try to build it if not provided)" valueName "<chain/bundle file>",
      opt[String]('p', "profile") optional() action { (x, c) =>
        c.copy(awsProfile = Some(x))
      } text "(optionally), AWS profile to provide credentials",
      opt[String]('r', "region") optional() action { (x, c) =>
        c.copy(awsRegionName = Some(x))
      } text "(optionally), AWS region to use - you may have already configured the region in your AWS profile",
      opt[String]("installProfile") optional() action { (x, c) =>
        c.copy(installProfile = Some(x)) } text "(optionally), an alternative AWS profile to install the cert in a different account\n",
      opt[String]("path") optional() action { (x, c) =>
        c.copy(path = Some(x))} text "(optionally), the certificate path; this must start with /cloudfront/ if you want to use it in Cloudfront",
      opt[String]('s', "service") optional() action { (x, c) =>
        c.copy(awsService = Some(x))
      } text "(optionally), AWS service - defaults to 'iam', accepted values: 'iam' 'apigateway'" validate ( x =>
        if (List("iam", "apigateway").contains(x)) success
        else failure("Option --service can only be 'iam' or 'apigateway'") )
      )
    cmd("tidy") action { (_, c) =>
      c.copy(mode = "tidy") } text "delete files associated with this domain" children(
        opt[String]('d', "domain") required() action { (x, c) => c.copy(domain = x) }
      )
    cmd("list") action { (_, c) => c.copy(mode = "list") } text "show pending CSRs and encrypted private keys"
  }

  parser.parse(args, Config()) foreach {
    case Config("create", domain, profile, _, _, force, regionNameOpt, _, _, _) =>
      Magic.create(domain, profile, force, regionNameOpt)

    case Config("install", _, profile, Some(certificateFile), chainFile, _, regionNameOpt, installProfile, path, service) =>
      Magic.install(profile, certificateFile, chainFile, regionNameOpt, installProfile, path, service)

    case Config("list", _, _, _, _, _, _, _, _, _) =>
      Magic.list()

    case Config("tidy", domain, _, _, _, _, _, _, _,_) =>
      Magic.tidy(domain)

    case _ =>
      parser.showUsage
  }
}
