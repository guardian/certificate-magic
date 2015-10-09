package com.gu.certificate

import java.io.File

import com.amazonaws.auth.profile.ProfileCredentialsProvider
import com.amazonaws.auth.{AWSCredentialsProvider, STSAssumeRoleSessionCredentialsProvider, _}
import com.amazonaws.regions.{Region, Regions}
import com.amazonaws.services.identitymanagement.AmazonIdentityManagementClient
import com.amazonaws.services.identitymanagement.model.UploadServerCertificateRequest
import org.joda.time.DateTime
import org.joda.time.format.ISODateTimeFormat

import scala.util.Try
import scalax.io.Resource


object Magic extends BouncyCastle with FileHelpers {

  def create(domain: String, awsProfile: Option[String], force: Boolean, regionNameOpt: Option[String]): Unit = {
    val region = getRegion(regionNameOpt)
    val safeDomain = safeDomainString(domain)
    val credentialsProvider = getCredentialsProvider(awsProfile)

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

  def install(keyProfile: Option[String], certificateFile: File, chainFile: Option[File], regionNameOpt: Option[String], installProfile:Option[String]): Unit = {
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

    System.err.println(s"installing to IAM")

    val iamClient = region.createClient(classOf[AmazonIdentityManagementClient], installCredentialsProvider, null)
    val uploadResult = iamClient.uploadServerCertificate(
      new UploadServerCertificateRequest()
        .withServerCertificateName(s"$safeDomain-exp$expDate")
        .withPrivateKey(decryptedPem)
        .withCertificateBody(certificatePem)
        .withCertificateChain(chainPem)
    )

    System.err.println(s"successfully installed certificate in IAM as ${uploadResult.getServerCertificateMetadata.getArn}")

    // TODO: [optionally?] delete the associated files so the private key is no longer around
  }

  def list(): Unit = {
    System.err.println("Currently created keys")
    // TODO: Read in subject from CSR and print in a more friendly format
    println(listFiles("csr").toSet)
    println(listFiles("pkenc").toSet)
  }

  private def safeDomainString(domain: String) = domain.replace("*", "star")

  private def assumeRole[T](underlyingProvider: AWSCredentialsProvider, roleArn: String)(block: AWSCredentialsProvider => T): T = {
    val dateTime = ISODateTimeFormat.basicDateTimeNoMillis().print(new DateTime())
    val userName = s"certificate-magic-$dateTime"

    val provider = new STSAssumeRoleSessionCredentialsProvider(underlyingProvider, roleArn, userName)
    // run code
    block(provider)
  }

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
