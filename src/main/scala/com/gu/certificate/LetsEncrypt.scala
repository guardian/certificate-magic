package com.gu.certificate

import java.io.StringReader
import java.security.KeyPair

import com.ning.http.client.Response
import dispatch.{Req, Http, url}
import it.zero11.acme.storage.impl.DefaultCertificateStorage
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import scala.collection.mutable.ListBuffer
import scala.concurrent.{Future, Await}
import scala.concurrent.ExecutionContext.Implicits.global
import org.json4s.DefaultFormats
import scala.concurrent.duration._

import it.zero11.acme.Acme

import scala.io.Source

trait LetsEncrypt extends BouncyCastle with FileHelpers {
  val CA_STAGING_URL = "https://acme-staging.api.letsencrypt.org/acme"

  lazy val acme = new Acme(CA_STAGING_URL, new DefaultCertificateStorage(), ???)

  lazy val userKeyPair: KeyPair = {
    val file = getFile("le-user-keypair.pem")
    if (file.exists) {
      println("Reading existing keypair")
      val content = file.string
      val pemKeyPair = readKeyPair(content)
      val converter = new JcaPEMKeyConverter()
      converter.getKeyPair(pemKeyPair.get)
    } else {
      println("Creating new keypair")
      val newKeyPair = createKeyPair()
      val pemKeyPair = toPem(newKeyPair)
      file.write(pemKeyPair)
      userKeyPair
    }
  }

  implicit val formats = DefaultFormats

  val apiUrl = "https://acme-staging.api.letsencrypt.org"

  val nonce = ListBuffer.empty[String]

  def http[T](request: Req)(f: Response => T): Future[T] = {
    Http(request OK { response =>
      nonce ++ Option(response.getHeader("replay-nonce"))
      f(response)
    })
  }

  def get(path:String) = {
    http(url(s"$apiUrl$path")) { response =>
      dispatch.as.json4s.Json(response)
    }
  }

  lazy val directory = Await.result(get("/directory") map { json => json.extract[Map[String,Any]] }, 10 seconds)

  def newAuth(domain: String) = {
    val url = directory("new-authz")

  }

  def newCert(domain: String) = {
    val url = directory("new-cert")

  }

  def shutdown() { Http.shutdown() }
}
