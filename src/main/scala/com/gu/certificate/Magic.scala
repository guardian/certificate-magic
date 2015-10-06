package com.gu.certificate

import java.io.File

import com.amazonaws.auth.profile.ProfileCredentialsProvider
import com.amazonaws.auth._
import com.amazonaws.regions.{Region, Regions}
import com.amazonaws.services.identitymanagement.AmazonIdentityManagementClient
import com.amazonaws.services.identitymanagement.model._
import org.joda.time.DateTime
import org.joda.time.format.ISODateTimeFormat

import scala.util.Try
import scalax.io.Resource

object Magic extends App with BouncyCastle with FileHelpers {
  case class Config(mode:String="", domain:String="", awsProfile:Option[String]=None, certificate:Option[File]=None, chain:Option[File]=None, force:Boolean=false, awsRegion:Option[String]=None)

  val parser = new scopt.OptionParser[Config]("magic") {
    head("certificate magic", "1.0")
    opt[String]('p', "profile") optional() action { (x, c) => c.copy(awsProfile = Some(x)) }
    opt[String]('r', "region") optional() action { (x, c) => c.copy(awsRegion = Some(x)) }
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

  def safeDomainString(domain: String): String = domain.replace("*", "star")

  def withTempCredentials[T](region: Region, policyArn: String)(block: AWSCredentialsProvider => T) = {
    val iamClient = region.createClient(classOf[AmazonIdentityManagementClient], null, null)

    // create credentials
    val dateTime = ISODateTimeFormat.basicDateTimeNoMillis().print(new DateTime())
    val userName = s"certificate-magic-$dateTime"
    iamClient.createUser(new CreateUserRequest().withUserName(userName))

    try {
      iamClient.attachUserPolicy(new AttachUserPolicyRequest().withUserName(userName).withPolicyArn(policyArn))
      val accessKeyResult = iamClient.createAccessKey(new CreateAccessKeyRequest().withUserName(userName))

      // create provider
      val provider:AWSCredentialsProvider =
        new AWSCredentialsProvider {
          def refresh() {}
          val getCredentials: AWSCredentials = new BasicAWSCredentials(
            accessKeyResult.getAccessKey.getAccessKeyId,
            accessKeyResult.getAccessKey.getSecretAccessKey
          )
        }

      // run code
      block(provider)
    } finally {
      // delete credentials
      iamClient.deleteUser(new DeleteUserRequest().withUserName(userName))
    }
  }

  def assumeRole[T](region: Region, roleArn: String)(block: AWSCredentialsProvider => T) = {
    val dateTime = ISODateTimeFormat.basicDateTimeNoMillis().print(new DateTime())
    val userName = s"certificate-magic-$dateTime"

    val provider = new STSAssumeRoleSessionCredentialsProvider(roleArn, userName)
    // run code
    block(provider)
  }

  parser.parse(args, Config()) foreach { config =>
    lazy val region = Region.getRegion(
      config.awsRegion
        .orElse(Option(System.getenv("AWS_DEFAULT_REGION")))
        .map(Regions.fromName)
        .getOrElse(Regions.EU_WEST_1)
    )

    lazy val provider = config.awsProfile.map { profile =>
      new ProfileCredentialsProvider(profile)
    }.getOrElse(new DefaultAWSCredentialsProviderChain())

    lazy val cryptProvider = new AwsEncryption(region, provider)

    config match {
      case Config("create", domain, profile, _, _, force, _) =>
        val safeDomain = safeDomainString(domain)
        // check if private key already exists
        if (!force) {
          val encryptedKey = getFile(safeDomain, "pkenc")
          if (encryptedKey.exists) throw new RuntimeException(s"Private key already exists at $encryptedKey, use --force to overwrite if you are sure you no longer need this private key")
        }

        // create keypair
        val keyPair = createKeyPair()
        val pkPem = toPem(keyPair.getPrivate)

        // encrypt private key with KMS
        val keyId = cryptProvider.getCertificateMagicKey
        val ciphertext = cryptProvider.encrypt(keyId, pkPem, domain)
        val pkEncFile = saveFile(ciphertext, safeDomain, "pkenc")

        // create CSR
        val csrPem = toPem(createCsr(keyPair, domain))
        // display/save CSR
        val csrFile = saveFile(csrPem, safeDomain, "csr")

        // give details to user
        println(csrPem)
        System.err.println(s"Written encrypted PK to $pkEncFile and CSR to $csrFile")

      case Config("install", _, _, Some(certificateFile), chainFile, _, _) =>
        // read in and inspect certificate
        val certificatePem = Resource.fromFile(certificateFile).string
        val certificate = readCertificate(certificatePem).getOrElse {
          throw new RuntimeException(s"Couldn't read certificate at $certificateFile")
        }
        val domain = getCommonName(certificate)
        val safeDomain = safeDomainString(domain)
        val expDate = ISODateTimeFormat.date().print(new DateTime(certificate.getNotAfter))

        // find and decrypt private key
        val readPkEncFile = Try(readBytes(safeDomain, "pkenc")).getOrElse {
          throw new RuntimeException(s"Couldn't find encrypted private key for $domain")
        }
        val decryptedPem = cryptProvider.decrypt(readPkEncFile, domain)

        // check certificate matches keypair
        val keypair = readKeyPair(decryptedPem).getOrElse(throw new RuntimeException(s"Couldn't read decrypted private key"))
        val keyPairPublicKey = keypair.getPublicKeyInfo.getPublicKeyData.getBytes.toList
        val certPublicKey = certificate.getSubjectPublicKeyInfo.getPublicKeyData.getBytes.toList
        assert(
          keyPairPublicKey == certPublicKey,
          s"Invalid certificate: Public key in certificate and public key in stored keypair do not match"
        )

        System.err.println(s"decrypted: $decryptedPem")

        // load or build chain
        val chainPem: String = chainFile.map { file =>
          Resource.fromFile(file).string
        }.getOrElse {
          getChainFromCertificate(certificate).map(toPem(_).trim).mkString("\n")
        }

        println(chainPem)

        // upload to AWS
        val iamClient = region.createClient(classOf[AmazonIdentityManagementClient], provider, null)
        iamClient.uploadServerCertificate(
          new UploadServerCertificateRequest()
            .withServerCertificateName(s"$safeDomain-exp$expDate")
            .withPrivateKey(decryptedPem)
            .withCertificateBody(certificatePem)
            .withCertificateChain(chainPem)
        )

        // TODO: [optionally?] delete the associated files so the private key is no longer around

      case Config("list", _, _, _, _, _, _) =>

        System.err.println("Currently created keys")
        // TODO: Read in subject form CSR and print in a more friendly format
        println(listFiles("csr").toSet)
        println(listFiles("pkenc").toSet)
    }
  }
}
