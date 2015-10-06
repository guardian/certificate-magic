package com.gu.certificate

import java.io.File

import com.amazonaws.auth.{AWSCredentialsProvider, STSAssumeRoleSessionCredentialsProvider}
import com.amazonaws.regions.{Region, Regions}
import com.amazonaws.services.identitymanagement.AmazonIdentityManagementClient
import com.amazonaws.services.identitymanagement.model.UploadServerCertificateRequest
import org.joda.time.DateTime
import org.joda.time.format.ISODateTimeFormat

import scala.util.Try
import scalax.io.Resource


object Magic extends BouncyCastle with FileHelpers {

  def create(domain: String, profile: Option[String], force: Boolean, regionNameOpt: Option[String]): Unit = {
    val region = getRegion(regionNameOpt)
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
    val aws = new AwsEncryption(region)
    val keyId = aws.getCertificateMagicKey
    val ciphertext = aws.encrypt(keyId, pkPem, domain)
    val pkEncFile = saveFile(ciphertext, safeDomain, "pkenc")

    // create CSR
    val csrPem = toPem(createCsr(keyPair, domain))
    // display/save CSR
    val csrFile = saveFile(csrPem, safeDomain, "csr")

    // give details to user
    println(csrPem)
    System.err.println(s"Written encrypted PK to $pkEncFile and CSR to $csrFile")
  }

  def install(profile: Option[String], certificateFile: File, chainFile: Option[File], regionNameOpt: Option[String]): Unit = {
    val region = getRegion(regionNameOpt)
    val aws = new AwsEncryption(region)

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
    val decryptedPem = aws.decrypt(readPkEncFile, domain)

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

    // upload to AWS
    assumeRole(region, "arn:aws:iam::aws:policy/IAMFullAccess") { provider =>
      val iamClient = region.createClient(classOf[AmazonIdentityManagementClient], provider, null)
      iamClient.uploadServerCertificate(
        new UploadServerCertificateRequest()
          .withServerCertificateName(s"$safeDomain-exp$expDate")
          .withPrivateKey(decryptedPem)
          .withCertificateBody(certificatePem)
          .withCertificateChain(chainPem)
      )
    }
  }

  def list(): Unit = {
    val csrNames = getFiles("csr") map (_.getName.stripSuffix(".csr"))
    System.err.println(csrNames mkString ", ")
  }

  private def safeDomainString(domain: String): String = domain.replace("*", "star")

  private def assumeRole[T](region: Region, roleArn: String)(block: AWSCredentialsProvider => T): T = {
    val dateTime = ISODateTimeFormat.basicDateTimeNoMillis().print(new DateTime())
    val userName = s"certificate-magic-$dateTime"

    val provider = new STSAssumeRoleSessionCredentialsProvider(roleArn, userName)
    // run code
    block(provider)
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
