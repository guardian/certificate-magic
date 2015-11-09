# Contributing to certificate-magic

:+1::tada: First off, thanks for taking the time to contribute! :tada::+1:

## Development Environment

At the time of writing, certificate-magic uses Scala 2.11.7 and SBT 0.13.9. Along with a recent JDK (e.g. OpenJDK 8 or Oracle JDK 1.8) you should be good to go.

## Running certificate-magic through SBT

You can use certificate-magic, as [outlined in the README](https://github.com/guardian/certificate-magic/blob/master/README.adoc), straight from SBT.

Inside SBT, simply substitute the `cert-magic` at the beginning of the desired command with `run`. For example:

```
> run list -p myprofile
[info] Running com.gu.certificate.Main list -p myprofile
Currently created keys
somedomain.com.csr
somedomain.com.pkenc
[success] Total time: 0 s, completed 09-Nov-2015 16:31:16
```

For all available options, please refer to the help text, which is accessible by calling `run` without any arguments:

```
> run
[info] Running com.gu.certificate.Main
certificate magic 1.0
Usage: magic [create|install|list|tidy] [options]
...
```