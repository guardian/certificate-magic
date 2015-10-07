package com.gu.certificate

import java.nio.charset.Charset
import java.nio.{ByteBuffer, CharBuffer}

import com.amazonaws.auth.AWSCredentialsProvider
import com.amazonaws.regions.Region
import com.amazonaws.services.kms.AWSKMSClient
import com.amazonaws.services.kms.model._

import scala.collection.JavaConverters._

class AwsEncryption(region: Region, provider: AWSCredentialsProvider) {
  val alias = "alias/certificate-magic"

  val charset = Charset.forName("UTF-8")
  val encoder = charset.newEncoder()
  val decoder = charset.newDecoder()

  val client = region.createClient(classOf[AWSKMSClient], provider, null)

  def createKeyWithAlias(alias: String) {
    val createKeyRequest = new CreateKeyRequest().withDescription("For securing private keys whilst getting certificates issued with certificate-magic")
    val createKeyResult = client.createKey(createKeyRequest)
    val key = createKeyResult.getKeyMetadata
    val createAliasRequest = new CreateAliasRequest().withAliasName(alias).withTargetKeyId(key.getKeyId)
    val createAliasResult = client.createAlias(createAliasRequest)
  }

  def getKeyIdWithAlias(alias:String): Option[String] = {
    val result = client.listAliases()
    result.getAliases.asScala.find(_.getAliasName == alias).map(_.getTargetKeyId)
  }

  def getCertificateMagicKey:String = {
    val keyId = getKeyIdWithAlias(alias)
    if (keyId.isDefined) keyId.get
    else {
      createKeyWithAlias(alias)
      getCertificateMagicKey
    }
  }

  def encrypt(keyId:String, plaintext:String, domain: String): ByteBuffer = {
    val plaintextBuffer:ByteBuffer = encoder.encode(CharBuffer.wrap(plaintext))
    val request = new EncryptRequest()
      .withKeyId(keyId)
      .withPlaintext(plaintextBuffer)
      .withEncryptionContext(Map("Domain" -> domain).asJava)
    val result = client.encrypt(request)
    result.getCiphertextBlob
  }

  def decrypt(ciphertext:ByteBuffer, domain: String): String = {
    val request = new DecryptRequest()
      .withCiphertextBlob(ciphertext)
      .withEncryptionContext(Map("Domain" -> domain).asJava)
    val result = client.decrypt(request)
    decoder.decode(result.getPlaintext).toString
  }

  def describeKey(id:String) = {
    val request = new DescribeKeyRequest().withKeyId(id)
    val result = client.describeKey(request)
    result.getKeyMetadata
  }
}
