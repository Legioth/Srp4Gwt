Srp4Gwt
=======

Implementation of the Secure Remote Password protocol for GWT.

## Security warning ##

It is necessary to always use SSL together with SRP since a man-in-the-middle could otherwise inject custom javascript that gets the password directly from the user.

Do not use trust this code without carefully verifying that the implementation is in fact correct.

## How to use ##

See `com.github.legioth.srp4gwt.demo` for an example of how to use the module.

You need to download version 2.3.0 of https://code.google.com/p/gwt-crypto/ and include it on you classpath.
