name := "certificate-magic"

version := "1.0-SNAPSHOT"

scalaVersion := "2.11.7"

libraryDependencies ++= Seq(
  "com.amazonaws" % "aws-java-sdk" % "1.10.22",
  "org.bouncycastle" % "bcprov-jdk15on" % "1.52",
  "org.bouncycastle" % "bcpkix-jdk15on" % "1.52",
  "com.github.scopt" %% "scopt" % "3.3.0",
  "com.github.scala-incubator.io" %% "scala-io-file" % "0.4.3",
  "org.scala-lang.modules" %% "scala-parser-combinators" % "1.0.4",
  "joda-time" % "joda-time" % "2.8.1",
  "org.joda" % "joda-convert" % "1.8",
  "org.scalatest" %% "scalatest" % "2.2.4" % "test",
  "net.databinder.dispatch" %% "dispatch-core" % "0.11.3",
  "net.databinder.dispatch" %% "dispatch-json4s-native" % "0.11.3",
  "org.glassfish.jersey.core" % "jersey-client" % "2.22.1",
  "io.jsonwebtoken" % "jjwt" % "0.6.0",
  "org.slf4j" % "slf4j-simple" % "1.7.13"
)

assemblyJarName in assembly := "cert-magic.jar"
