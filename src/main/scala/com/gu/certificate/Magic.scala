package com.gu.certificate

import java.io.File

import com.amazonaws.auth.profile.ProfileCredentialsProvider
import com.amazonaws.auth.{AWSCredentialsProvider, STSAssumeRoleSessionCredentialsProvider, _}
import com.amazonaws.regions.{Region, Regions}
import com.amazonaws.services.identitymanagement.AmazonIdentityManagementClient
import com.amazonaws.services.apigateway.AmazonApiGatewayClient
import com.amazonaws.services.apigateway.model.{CreateDomainNameRequest, TooManyRequestsException}
import com.amazonaws.services.identitymanagement.model.{LimitExceededException, UploadServerCertificateRequest}
import org.joda.time.DateTime
import org.joda.time.format.ISODateTimeFormat

import scala.util.Try
import scalax.file.Path
import scalax.io.Resource


object Magic extends BouncyCastle with FileHelpers {

  def create(domain: String, awsProfileOpt: Option[String], force: Boolean, regionNameOpt: Option[String]): Unit = {
    val region = getRegion(regionNameOpt)
    val safeDomain = safeDomainString(domain)
    val credentialsProvider = getCredentialsProvider(awsProfileOpt)

    // check if private key already exists
    if (!force) {
      val encryptedKey = getFile(safeDomain, "pkenc")
      if (encryptedKey.exists) throw new RuntimeException(s"Private key already exists at $encryptedKey, use --force to overwrite if you are sure you no longer need this private key")
    }

    // create keypair
    val keyPair = createKeyPair()
    val pkPem = toPem(keyPair.getPrivate)

    // encrypt private key with KMS
    val cryptProvider = new AwsEncryption(region, credentialsProvider)
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
  }

  def install(keyProfile: Option[String], certificateFile: File, chainFile: Option[File], regionNameOpt: Option[String], installProfile:Option[String], path:Option[String], service:Option[String]): Unit = {
    val region = getRegion(regionNameOpt)
    val keyCredentialsProvider = getCredentialsProvider(keyProfile)
    val installCredentialsProvider = installProfile.map(ip => getCredentialsProvider(Some(ip))).getOrElse(keyCredentialsProvider)

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
    val cryptProvider = new AwsEncryption(region, keyCredentialsProvider)
    val decryptedPem = cryptProvider.decrypt(readPkEncFile, domain)

    // check certificate matches keypair
    val keypair = readKeyPair(decryptedPem).getOrElse(throw new RuntimeException(s"Couldn't read decrypted private key"))
    val keyPairPublicKey = keypair.getPublicKeyInfo.getPublicKeyData.getBytes.toList
    val certPublicKey = certificate.getSubjectPublicKeyInfo.getPublicKeyData.getBytes.toList
    assert(
      keyPairPublicKey == certPublicKey,
      s"Invalid certificate: Public key in certificate and public key in stored keypair do not match"
    )

    System.err.println(s"successfully decrypted private key")

    // load or build chain
    val chainPem: String = chainFile.map { file =>
      Resource.fromFile(file).string
    }.getOrElse {
      getChainFromCertificate(certificate).map(toPem(_).trim).mkString("\n")
    }

    val pathPrefix = path.getOrElse("").stripPrefix("/").replace("/", "-")
    val certificateName = s"$pathPrefix$safeDomain-exp$expDate"

    service match {
      case Some("iam") => installToIAM(path, region, installCredentialsProvider, certificateName, decryptedPem, certificatePem, chainPem)
      case Some("apigateway") => installToGateway(region, installCredentialsProvider, safeDomain, certificateName, decryptedPem, certificatePem, chainPem)
      case _ => None
    }
  }

  def installToIAM (path: Option[String], region: Region, installCredentialsProvider: AWSCredentialsProvider, certificateName: String, decryptedPem: String, certificatePem: String, chainPem: String) {
    System.err.println(s"installing to IAM")

    val iamClient = region.createClient(classOf[AmazonIdentityManagementClient], installCredentialsProvider, null)
    val certificateUploadRequest = new UploadServerCertificateRequest()
      .withServerCertificateName(certificateName)
      .withPrivateKey(decryptedPem)
      .withCertificateBody(certificatePem)
      .withCertificateChain(chainPem)
      .withPath(path.getOrElse("/"))

    Try {
      val certificateUploadResult = iamClient.uploadServerCertificate(certificateUploadRequest)
      val certificateArn = certificateUploadResult.getServerCertificateMetadata.getArn
      System.err.println(s"successfully installed certificate in IAM as ${certificateArn}")
    } recover {
      case e: LimitExceededException => System.err.println("You have reached the ServerCertificatesPerAccount limit for your account. Request more by opening a support ticket with AWS.")
      case e: Throwable => System.err.println(s"An error occurred during upload: ${e}")
    }
  }

  def installToGateway (region: Region, installCredentialsProvider: AWSCredentialsProvider, safeDomain: String, certificateName: String, decryptedPem: String, certificatePem: String, chainPem: String): Unit = {
    System.err.println(s"installing to API GateWay")

    val client = region.createClient(classOf[AmazonApiGatewayClient], installCredentialsProvider, null)
    val createDomainNameRequest = new CreateDomainNameRequest()
      .withDomainName(safeDomain)
      .withCertificateName(certificateName)
      .withCertificateBody(certificatePem)
      .withCertificatePrivateKey(decryptedPem)
      .withCertificateChain(chainPem)

    Try {
      val createDomainNameResult = client.createDomainName(createDomainNameRequest)
      val distributionDomainName = createDomainNameResult.getDistributionDomainName
      System.err.println(s"successfully created an API GateWay domain name as $distributionDomainName")
    } recover {
      case e: TooManyRequestsException => System.err.println(s"You have reached the create domain name limit for your account. Retry in ${e.getRetryAfterSeconds} seconds.")
      case e: Throwable => System.err.println(s"An error occurred during domain name creation: $e")
    }
  }

  def list(): Unit = {
    System.err.println("Currently created keys")
    // TODO: Read in subject from CSR and print in a more friendly format
    println(listFiles("csr").toSet.map((path: Path) => path.name).mkString(" "))
    println(listFiles("pkenc").toSet.map((path: Path) => path.name).mkString(" "))
  }

  def tidy(domain: String): Unit = {
    val safeDomain = safeDomainString(domain)
    // check if there are files to tody up
    val csrExists = exists(safeDomain, "csr")
    val pkencExists = exists(safeDomain, "pkenc")

    if (!pkencExists && !csrExists) {
      System.err.println(s"No files found for $domain, nothing to tidy up")
    } else {
      // prompt for confirmation
      if (csrExists) System.err.println(s"CSR file for $domain will be deleted")
      if (pkencExists) System.err.println(s"Encrypted private key for $domain will be deleted")
      System.err.println(s"${Console.BOLD}make sure you have tested the certificate is correctly installed before running this command${Console.RESET}")
      System.err.print("proceed [y/N] ")
      Console.out.flush()
      val choice = scala.io.StdIn.readLine()
      if (choice.toLowerCase == "y") {
        // delete files
        if (csrExists) {
          deleteFile(safeDomain, "csr")
          println(s"deleted $safeDomain.csr")
        }
        if (pkencExists) {
          deleteFile(safeDomain, "pkenc")
          println(s"deleted encrypted private key $safeDomain.pkenc")
        }
      }
    }
  }

  private def safeDomainString(domain: String) = domain.replace("*", "star")

  private def getCredentialsProvider(awsProfile: Option[String]): AWSCredentialsProvider = {
    awsProfile.map { profile =>
      new ProfileCredentialsProvider(profile)
    }.getOrElse(new DefaultAWSCredentialsProviderChain())
  }

  private def getRegion(regionNameOpt: Option[String]): Region = {
    Region.getRegion(
      regionNameOpt
        .orElse(Option(System.getenv("AWS_DEFAULT_REGION")))
        .map(Regions.fromName)
        .getOrElse(Regions.EU_WEST_1)
    )
  }
}
