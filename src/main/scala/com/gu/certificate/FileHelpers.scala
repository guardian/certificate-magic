package com.gu.certificate

import java.io.File
import java.nio.ByteBuffer

import scalax.file.{Path, PathSet}

trait FileHelpers {
  lazy val homeDir = Option(System.getProperty("user.home"))
  lazy val magicDir = s"${homeDir.get}/.magic"
  lazy val magicPath = Path.fromString(magicDir)

  def getFile(domain:String, ext:String) = {
    magicPath.createDirectory(createParents = true, failIfExists = false)
    magicPath / s"$domain.$ext"
  }

  def listFiles(ext:String): PathSet[Path] = {
    if (magicPath.exists) magicPath ** s"*.$ext"
    else PathSet()
  }

  def saveFile(content:String, domain:String, ext:String): File = {
    val file = getFile(domain, ext)
    file.write(content)
    file.fileOption.get
  }

  def saveFile(content:ByteBuffer, domain:String, ext:String): File = {
    val file = getFile(domain, ext)
    file.write(content)
    file.fileOption.get
  }

  def readBytes(domain:String, ext:String): ByteBuffer = {
    val file = getFile(domain, ext)
    ByteBuffer.wrap(file.byteArray)
  }

  def deleteFile(domain: String, ext: String): Unit = {
    val file = getFile(domain, ext)
    file.delete()
  }

  def exists(domain: String, ext: String): Boolean = {
    val file = getFile(domain, ext)
    file.exists
  }
}
