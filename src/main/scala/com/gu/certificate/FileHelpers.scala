package com.gu.certificate

import java.io.{FilenameFilter, File}
import java.nio.ByteBuffer

import scalax.file.Path
import scalax.file.defaultfs.DefaultPath

trait FileHelpers {
  def homeDir = Option(System.getProperty("user.home"))
  private val path = Path.fromString(s"${homeDir.get}/.certmagic")

  def getFile(domain:String, ext:String): DefaultPath = {
    path.createDirectory(createParents = true, failIfExists = false)
    path / s"$domain.$ext"
  }

  def getFiles(ext: String): List[File] = {
    val filenameFilter: FilenameFilter = new FilenameFilter {
      override def accept(dir: File, name: String): Boolean = name.endsWith(s".$ext")
    }
    if (path.exists) {
      path.fileOption map { file =>
        file.listFiles(filenameFilter).toList
      } getOrElse Nil
    } else Nil
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
