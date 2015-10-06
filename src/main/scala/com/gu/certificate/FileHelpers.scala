package com.gu.certificate

import java.io.File
import java.nio.ByteBuffer

import scalax.file.Path
import scalax.file.defaultfs.DefaultPath

trait FileHelpers {
  def homeDir = Option(System.getProperty("user.home"))

  def getFile(domain:String, ext:String): DefaultPath = {
    val path = Path.fromString(s"${homeDir.get}/.magic")
    path.createDirectory(createParents = true, failIfExists = false)
    path / s"$domain.$ext"
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

}
