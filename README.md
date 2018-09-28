# einstein

Einstein provides a communication interface for Philips IntelliVue Patient Monitors.


## What is it?

Philips IntelliVue Patient Monitors ("IntelliVues") natively export data through means of a proprietary API over UDP.

Einstein is a service that connects to IntelliVues and provides an HTTP/JSON API,
to make it easier for applications on top to work with the data.

Einstein essentially consists of two parts;
packet definitions and interfacing tools for the IntelliVue protocol (largely built with [Scapy](https://scapy.net/)),
and the engine for handling high-level communications and state with IntelliVue devices and HTTP clients (largely built with [Twisted](https://twistedmatrix.com/)).


## References

Much of this work was built based on the Philips IntelliVue Patient Monitor DATA EXPORT INTERFACE
PROGRAMMING GUIDE for the X2, MP Series, MX Series - id 4535 642 59271 - the "Philips Interface Programming Guide".

Internal references of the form "PIPG-1" refer to page 1 of this document.


## Why "einstein"?

It needed a name,
Kristian Glass built the initial version,
it communicates with Philips monitors,
and Philip Glass wrote Einstein on the Beach...


## How to run this software

    pipenv install
    pipenv shell
    python einstein/server.py
