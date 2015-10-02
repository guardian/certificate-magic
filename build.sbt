name := "certificate-magic"

version := "1.0-SNAPSHOT"

scalaVersion := "2.11.7"

libraryDependencies ++= Seq(
  "com.amazonaws" % "aws-java-sdk" % "1.9.3",
  "org.bouncycastle" % "bcprov-jdk15on" % "1.52",
  "org.bouncycastle" % "bcpkix-jdk15on" % "1.52",
  "com.github.scopt" %% "scopt" % "3.3.0",
  "com.github.scala-incubator.io" %% "scala-io-file" % "0.4.3",
  "org.scala-lang.modules" %% "scala-parser-combinators" % "1.0.4",
  "org.scalatest" %% "scalatest" % "2.2.4" % "test"
)