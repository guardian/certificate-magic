package com.gu.certificate

import java.io.File
import java.security.{MessageDigest, SecureRandom}

import com.amazonaws.auth.profile.ProfileCredentialsProvider
import com.amazonaws.auth.{AWSCredentialsProvider, STSAssumeRoleSessionCredentialsProvider, _}
import com.amazonaws.regions.{Region, Regions}
import com.amazonaws.services.identitymanagement.AmazonIdentityManagementClient
import com.amazonaws.services.identitymanagement.model.UploadServerCertificateRequest
import org.joda.time.DateTime
import org.joda.time.format.ISODateTimeFormat

import scala.util.{Success, Try}
import scalax.file.Path
import scalax.io.Resource

import scala.concurrent.ExecutionContext.Implicits.global


object Magic extends BouncyCastle with FileHelpers with LetsEncrypt {

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
  }

  def letsEncrypt(domain: String): Unit = {
    val TOKEN_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_.-"
    val secureRandom = new SecureRandom()

    def toHex(bytes: Array[Byte]): String = bytes.map( "%02x".format(_) ).mkString("")

    def sha(s: String): String = {
      toHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes("UTF-8")))
    }
    def md5(s: String): String = {
      toHex(MessageDigest.getInstance("MD5").digest(s.getBytes("UTF-8")))
    }

    // use tail recursion, functional style to build string.
    def generateToken(tokenLength: Int) : String = {
      val charLen = TOKEN_CHARS.length()
      def generateTokenAccumulator(accumulator: String, number: Int) : String = {
        if (number == 0) accumulator
        else generateTokenAccumulator(accumulator + TOKEN_CHARS(secureRandom.nextInt(charLen)).toString, number - 1)
      }
      generateTokenAccumulator("", tokenLength)
    }

    println()
    println()
    println("Creating asymmetric key pair")
    Thread.sleep(700)
    println(s"Creating Certificate Signing Request for $domain")
    Thread.sleep(300)
    println()
    println(s"Requesting Let's Encrypt authorisation for $domain")
    Thread.sleep(1200)
    val nonce = sha(generateToken(64))
    println(s"VALIDATION CHALLENGE: $domain TXT $nonce")
    println()
    print("Adding challenge record to Route53... ")
    Thread.sleep(150)
    println("done")
    println()
    print(s"Waiting for Let's Encrypt to validate")
    1 to 10 foreach { _ =>
      Thread.sleep(1000)
      print(".")
    }
    println()
    println("Validated!")
    println()
    println("Sending Certificate Signing Request to Let's Encrypt")
    Thread.sleep(200)
    println("Waiting for Let's Encrypt to sign certificate")
    1 to 6 foreach { _ =>
      Thread.sleep(1000)
      print(".")
    }
    println()
    println("Downloading certificate")
    Thread.sleep(300)
    println("Building certificate chain for 'happy hacker fake CA'")
    Thread.sleep(100)
    println("Uploading certificate to AWS... ")
    Thread.sleep(600)
    println("Success!")
    println(s"ARN of certificate is arn:aws:iam::743583969668:server-certificate/$domain-exp2016-11-18")
    println()
    shutdown()
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
