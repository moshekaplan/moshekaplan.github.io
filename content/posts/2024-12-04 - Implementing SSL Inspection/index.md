---
title: "Implementing SSL Inspection"
date: 2024-12-04T08:00:00-04:00
draft: false
---

SSL inspection is an amazing technology for empowering network defenders. However, because it can potentially break every single HTTPS connection in your network it's important to deploy it carefully to avoid major outages. This writeup aims to give a basic overview of SSL inspection and how to deploy it in an enterprise environment to help avoid some of those issues.

# What is SSL and how does it work?
 <!---
* What is the problem with plaintext communication?
* How does SSL solve that problem? 
# How does SSL work?
* What is a certificate? 
* What is a certificate chain? 
* What is a certificate store? 
--->

Internet traffic goes through many devices before it reaches its destination. Those devices are not guaranteed to be well-intentioned. There are numerous stories of attackers intercepting traffic to either snoop or modify it. SSL (Secure Sockets Layer) was created to protect Internet traffic from attackers. Newer versions of this technology are called Transport Layer Security (TLS)[^1] and they are sometimes referred to together as SSL/TLS. 

[^1]: According to Tim Dierks, the entire renaming from SSL to TLS was part of a negotiation between Netscape and Microsoft so that it wouldn't look like the IETF was simply adopting Netscape's implementation. For more info, see https://tim.dierks.org/2014/05/security-standards-and-name-changes-in.html .

TLS operates by establishing a secure tunnel between a client, like a web browser, and a web server. This TLS tunnel is then used for sending and receiving web request data in a _TLS session_. Because the traffic sent through the TLS tunnel is encrypted, attackers cannot see the contents - it will only look like random data. TLS also adds integrity protections to detect if an attacker from modifyies the contents. These secure tunnels can be created over an untrusted Internet connection through the cryptographic wizardry known as [public-key cryptography](https://en.wikipedia.org/wiki/Public-key_cryptography)[^2].

[^2]: There are a few algorithms for doing this, including [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) and [Diffie-Hellman](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange), which are respectively based on how factoring large prime numbers and group theory.

However, there is still a problem of identity: How do you know _who_ you are establishing the secure tunnel with? For example, say you want to shop on Amazon.com. What's to stop an attacker from pretending to be Amazon.com and then you'd establish a secure connection with the attacker?

This identity verification is performed with something called an "SSL Certificate". As part of your computer establishing the secure tunnel, the website sends a "certificate" including which domain names are trusted to be secured for this communication.

![Image](<1. Amazon SSL cert.png> "Amazon.com SSL certificate")

Of course, this begs the obvious follow-up question: How do we know if we can trust a certificate? What's to stop an attacker from generating their own certificate for Amazon.com?

We can determine if a certificate is trusted based on who signed it: If we don't recognize a certificate, but the certificate is signed by someone else that we trust, we can also trust the certificate. For example, Amazon.com's certificate is signed by _DigiCert Global CA G2_. And _DigiCert Global CA G2_ is signed by _DigiCert Global Root G2_. Because my web browser trusts _DigiCert Global Root G2_, it therefore can trust the Amazon.com certificate and use it to establish a secure connection.

![Image](<2. Amazon SSL Chain.png> "Amazon.com SSL certificate chain")

However, we have only transferred the problem: How does my web browser know to trust certificates signed by _DigiCert Global Root G2_? The solution is that every computer is preloaded with something called a _certificate store_. The certificate store is a local list of certificates which the system trusts.  Because _DigiCert Global Root G2_ is my system's certificate store, my browser trusts it.

![Image](<3. System Certificates.png> "DigiCert Global Root G2 present in a Windows system's certificate store")

# What is SSL Inspection?
 <!---
* SSL as a problem -> No visibility into web traffic for other security capabilities (IDS, DLP, URL Filtering, external devices like full PCAP or Zeek)
* SSL inspection as a solution 
* * How SSL inspection could work with the certificate and private key  
* * How SSL inspection often uses a signing cert from a custom CA to avoid MITM errors 
* * Note that this is only possible with a custom CA loaded in the cert store 
--->

SSL and TLS are amazing developments for improving user privacy and security built on decades of cryptographic research. However, they can also cause a problem for network defenders: Because the Internet traffic is encrypted so that only the recipient can see the contents, it's not possible for network security tools to examine the traffic's contents. If network security tools cannot scan the contents of a secure connection:
* They cannot detect malware being downloaded
* They cannot determine if a website is trying to exploit a vulnerability
* They cannot see if sensitive information is exiting the network
* They cannot prevent access to websites not allowed per corporate policy (e.g., social media or adult content)

These limitations make it extremely difficult to implement effective enterprise network security controls. Enter SSL inspection.

The idea of SSL inspection is that there be a network security device that intercepts every single SSL or TLS connection so that network security tools can inspect the contents of the secure tunnel. The contents can then be examined however the network security team desires.

The SSL interception is implemented by replacing the web server's certificate with a new certificate signed by the interception device. The client would also need to have the SSL interception device's certificate or a higher-level certificate in its chain added to its certificate store, to avoid failing certificate validation.

# Implementing SSL Inspection

SSL inspection is a very intrusive activity and so it is not realistic to deploy a 'passive' or an 'out-of-bound' implementation for testing the deployment. So the only thing you can do to minimize the changes of a major outage is to slowly enable SSL inspection for different parts of the enterprise so that if there is a failure, it can be quickly detected before too many systems are negatively impacted. In practice, this might be based on network segments, subnets, groups of users, or system types.

You'll also need to build out your SSL bypasses: These are which connections will not be subjected to SSL inspection. The caveat to be aware of here is that you can only hinge SSL bypasses based on information which is available to a passive eavesdropper. So you can't create an SSL bypass based on a particular webpage, because which exact webpage is being requested is only available after the traffic is decrypted. For example, you might choose to bypass SSL inspection based on:
* Source address
* Destination address
* Destination port
* Certificate subject
* Website category
* Server Name Indication (SNI)

Most of these are self-explanatory. For example, you may have appliance-based systems that need to have all traffic bypassed, you may need to bypass traffic to vendor servers used for downloading updates, and you may have a policy requirement to exempt certain categories of domains, like healthcare websites in an environment subject to HIPAA. You may choose to limit the destination ports to TCP 443, or otherwise expand it to include other ports you generally allow like TCP 80.

The [Server Name Indication (SNI)](https://en.wikipedia.org/wiki/Server_Name_Indication) field is an extremely interesting field. SNI is a TLS extension which provides a means for a client to indicate to a server which hostname it wants to connect to. Therefore, a single server can choose which SSL certificate to return, based on the SNI's value. Prior to SNI's creation, each HTTPS server required a dedicated IP address, as the server had no way of determining which certificate to present to a client. Most modern web clients send an SNI by default and so the SSL inspection solution can use that to determine whether or not to inspect the traffic. This often also powers the web categorization - once the SSL inspection system has a hostname, it can look up the hostname's category.

![Image](<4. SNI example.png> "Wireshark screenshot of the SNI extension")

Another decision point is to determine whether your SSL inspection solution will be used as a technical control to block insecure SSL/TLS connections. For example, you may choose to use your SSL inspection solution as a policy enforcement point to block TLS 1.0 and TLS 1.1 connections.

As part of your phased rollout, you'll also want to include performance monitoring. SSL inspection consumes a significant amount of resources and once enabled, may cause other resource-intensive functionality, like antivirus scanning, to become enabled, as the network traffic contents will now be available.

# SSL Inspection Challenges 

While deploying SSL inspection is straightforward, there are several situations in which it can get messy.

## Separate certificate store

Before enabling SSL inspection it's important that the certificate used to sign the SSL inspection certificates be trusted by all systems on the network. Otherwise, the client will fail to validate the certificate and block the connection. To avoid this problem, the system administrators need to deploy the certificate used within the SSL inspection solution to the system's certificate stores. However, the problem is that although many applications use the system's certificate store, there are plenty of applications like Python, Java, and Firefox, which use their own per-application certificate store. The best solution here is to have an organization-maintained package which also includes the certificate, and so any user installing something like Python will have the certificate installed too.

In Python, you can control the certificate used by Python's Pip through the [pip.ini](https://pip.pypa.io/en/stable/topics/https-certificates/) file. On Windows, [this would be located in `C:\ProgramData\pip\pip.ini`](https://pip.pypa.io/en/stable/topics/configuration/#location)

```ini
[global]
cert = C:\ProgramData\pip\mybundle.pem
```
Similarly, Anaconda Python supports setting the SSL certificate configuration globally through a `conda config` command:
`conda config --set ssl_verify "C:\ProgramData\pip\mybundle.pem"`

[Python requests uses the `REQUESTS_CA_BUNDLE` environment variable](https://requests.readthedocs.io/en/latest/user/advanced/#proxies) and [Curl uses the `CURL_CA_BUNDLE` environment variable](https://curl.se/docs/sslcerts.html).

Java uses the `keytool` application to import a certificate into it's 'keystore' file, which is its name for the Java installation's certificate store.

## Client certificates

In most TLS connections, the client is anonymous and only authenticates the server based on the provided certificate. However, some websites actually mandate that the client identify itself via a _client certificate_. Client certificates are fundamentally incompatible with SSL inspection because the SSL inspection solution does not have the ability to replicate the client certificate. The only solution is to bypass sites that require client certificate from SSL inspection.

The one nice thing about client certificates is that it's possible to detect their usage with other tools prior to enabling SSL inspection. For example, Zeek x509 logs contain a _client_cert_ field which "Indicates if this certificate was sent from the client"[^3].

[^3]: Zeek x509 docs are available [here](https://docs.zeek.org/en/lts/scripts/base/files/x509/main.zeek.html#type-X509::Info)

## Certificate pinning

In an SSL inspection solution, the SSL inspection system replaces the SSL certificate the client sees with one that it generates. However, some applications _pin_ the certificate and require that a particular certificate be present. It is also not usually possible to add your own certificate to the list of allowed certificates. This is fairly uncommon for desktop software, but is far more common for mobile applications, where developers can easily deploy their certificate with the application. Unfortunately, there is no way to detect certificate pinning prior to deployment and so the only thing you can do is look for errors after enabling SSL inspection.

## Unsupported ciphersuites

In a normal TLS handshake, the client and the server together negotiate the _ciphersuite_, which are the cryptographic parameters used to create the TLS connection. However, it's possible that the only ciphersuites the server supports are not supported by the SSL inspection solution. When this occurs, a website that is accessible outside of your enterprise network will not be accessible through your SSL inspection solution. This issue seems to be most common for elliptical curve points. If connectivity is required, the only solution is to bypass SSL inspection for the target site.

## Replicating certificate failures

As part of establishing a TLS connection, the client validates the certificate and ensures that it's not expired, the subject matches the domain, and more. However, SSL inspection solutions do not always perform the same certificate validation[^6]. So it's possible for an external user to visit the site and receive a warning that the certificate is expired, but when an enterprise user visits the site, they do not receive any errors. This default behavior is concerning because it means that the SSL inspection solution has weakened user's security. The takeaway here is that it's important to validate the SSL inspection system's configuration to ensure that it is securely handling all of the failure cases similar to how a normal client, like Chrome, would. A great website for testing this is [BadSSL.com](https://badssl.com/) .

A related issue is that in order for an SSL inspection appliance to flag untrusted root certificates, it needs to have its own certificate store. It is important to maintain this internal store, as [sometimes certificates need to be removed from the certificate store](https://www.forbes.com/sites/daveywinder/2024/07/01/new-chrome-security-rules-google-gives-web-users-until-111-to-comply/).

[^6]: For more on this topic, see: [HTTPS Interception Weakens TLS Security](https://www.cisa.gov/news-events/alerts/2017/03/16/https-interception-weakens-tls-security), [The Risks of SSL Inspection](https://insights.sei.cmu.edu/blog/the-risks-of-ssl-inspection/), [The Sorry State of TLS Security in Enterprise Interception Appliances (2018-09-24)](https://arxiv.org/pdf/1809.08729), and [MANAGING RISK FROM TRANSPORT LAYER SECURITY INSPECTION (2019-12-16)](https://media.defense.gov/2019/Dec/16/2002225460/-1/-1/0/INFO%20SHEET%20%20MANAGING%20RISK%20FROM%20TRANSPORT%20LAYER%20SECURITY%20INSPECTION.PDF)


## Missing intermediate certificate 

Most websites use multiple tiers of certificate signing, where you have:
* A root certificate (e.g.,  _DigiCert Global Root G2_)
* An intermediate certificate (e.g., _DigiCert Global CA G2_)
* And a leaf certificate (e.g., Amazon.com)

An example of this can be seen in the screenshot below:

![Image](<2. Amazon SSL Chain.png> "Amazon.com SSL certificate chain")

When the client connects to the web server, the client needs to have a copy of each certificate in the chain so that it can validate each one. The root certificate must always be present in the client's certificate store - otherwise, validation would fail as an untrusted certificate. The leaf certificate must similarly always be presented by the web server - because otherwise, there is nothing to validate. But the intermediate certificate is often both not in the client's certificate store and also not presented by the web server.

If an intermediate certificate is missing, Chrome and Firefox use something called AIA (Authority Information Access) to dynamically retrieve the intermediate certificate, so that it can validate the entire chain and allow the user to access the site. However, not all SSL inspection solutions support AIA and so if an enterprise user attempts to visit a site missing the intermediate certificate, they may receive an error that the web server's certificate is untrusted. The solution for this problem would be to load the intermediate certificate into the SSL inspection solution so that it would be able to complete SSL certificate validation, even when the web server does not present the intermediate certificate.

# Other problems

There are also some other challenges related to SSL inspection that there aren't good answers to.

## QUIC
The most common protocol used for establishing secure connections to webservers is HTTPS, which uses TLS and operates over TCP port 443. However, Google created QUIC as a more efficient protocol for making secure web requests and it operates over UDP 443. The problem is, not all SSL inspection solutions support QUIC. So if a client uses QUIC to connect to a webserver, the SSL inspection solution will not inspect that traffic and so will not have any visibility into it. As such, several vendors (like [ZScaler](https://help.zscaler.com/zia/managing-quic-protocol), [A10](https://www.a10networks.com/blog/clearing-ssl-inspection-confusion/), and [Palo Alto](https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000ClarCAC) still recommend blocking QUIC at the perimeter to prevent enterprise users from effectively bypassing SSL inspection. Hopefully, more SSL inspection solutions will add support for QUIC and then it will no longer need to be blocked.

## Encrypted SNI and Encrypted Client Hello

As part of deploying SSL inspection, it's important to bypass domains that don't support SSL inspection that your users need to access. One of the more popular criteria is to use the Server Name Indication (SNI) so that domains can be bypassed from SSL inspection no matter which IPs the webserver uses. However, SNI has long been seen as harmful to privacy, as it enables a passive attacker to see which domain the user is visiting.

To increase user privacy, Encrypted SNI (ESNI) and Encrypted Client Hello (ECH) were developed as TLS 1.3 extensions to encrypt the SNI and other parts of the TLS handshake. The problem is that if the SNI is encrypted the SSL inspection solution cannot use the SNI to determine whether or not to bypass SSL inspection.

## Domain fronting

Domain fronting is when an attacker sends an SNI with one domain, but actually requests another domain in the HTTP HOST header. This is sometimes possible when communicating with a content delivery network, which splits the TLS session establishment from the actual web request processing. Domain fronting is problematic because SSL inspection might be bypassed for one domain, but the traffic is really intended for another domain.[^5]

[^5]: See [Domain Fronting with CloudFront](https://digi.ninja/blog/cloudfront_example.php) and [using domain fronting to mask your C2 traffic](https://n3dx0o.medium.com/using-domain-fronting-to-mask-your-c2-traffic-3099ae601685)

## Oblivious HTTP

In most web server deployments, the web server knows exactly which client IP is connecting to it. While it is possible for a client to mask its IP by using a proxy, the proxy would then have full access to the unencrypted traffic intended for the server. [Oblivious HTTP](https://en.wikipedia.org/wiki/DNS_over_HTTPS#Oblivious_DNS_over_HTTPS) is a draft protocol for sending an encrypted HTTP request to a proxy so that the proxy cannot see the contents of the request and the web server will not know the IP of the client connecting to it.

The problem Oblivious HTTP makes for SSL inspection is obvious: Because there is a second layer of encryption that the SSL inspection appliance cannot decrypt, it cannot see the unencrypted traffic. I have not seen any discussion on the topic, but I would be most interested in seeing if there has been any research on implementing SSL inspection for connections to an Oblivious HTTP proxy.

# Conclusion

While this was fairly long, it feels like it only scratched the surface of SSL inspection and its challenges. It will be interesting to see how the landscape changes and how vendors will react to it. Will the vendors all add support for decrypting QUIC? Will certificate pinning become more popular? Will more applications use their own certificate store? Will ESNI or ECH become common? Only time will tell for all of these.

# Further Reading
* [What Is SSL Web Inspection and Where Should It Occur? (Part 3) (2018-02-06)](https://www.optiv.com/explore-optiv-insights/blog/what-ssl-web-inspection-and-where-should-it-occur-part-3)
* [Hanno Böck: The Rocky Road to TLS 1.3 and better Internet Encryption (35C3, 2018-12-27)](https://media.ccc.de/v/35c3-9607-the_rocky_road_to_tls_1_3_and_better_internet_encryption)
* [Hanno Böck: Some tales from TLS (2015-04-04)](https://www.youtube.com/watch?v=f92iRioy6ss)
* [DEF CON 32 - Breaking Secure Web Gateways for Fun and Profit -Vivek Ramachandran, Jeswin Mathai](https://www.youtube.com/watch?v=mBZQnJ1MWYI)
* [Squid-in-the-middle SSL Bump](https://wiki.squid-cache.org/Features/SslBump)
* [Introducing Zero Round Trip Time Resumption (0-RTT) (2017-03-15)](https://blog.cloudflare.com/introducing-0-rtt/)
* [Cisco Secure Firewall Decryption Policy Guidance](https://secure.cisco.com/secure-firewall/docs/decryption-policy)
* [Best Practices for Enabling SSL Decryption](https://www.paloaltonetworks.com/blog/2018/11/best-practices-enabling-ssl-decryption/)
* [How to Implement and Test SSL Decryption](https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000ClEZCA0&lang=en_US)
* [Why does Wireshark show Version TLS 1.2 here instead of TLS 1.3?](https://networkengineering.stackexchange.com/questions/55752/why-does-wireshark-show-version-tls-1-2-here-instead-of-tls-1-3)
* [Sharkfest 24 - Real-world post-quantum TLS in Wireshark](https://lekensteyn.nl/files/wireshark-pq-tls-sharkfest24us.pdf)
* [A Survey of TLS 1.3 0-RTT Usage](https://ethz.ch/content/dam/ethz/special-interest/infk/inst-infsec/appliedcrypto/education/theses/masters-thesis_mihael-liskij.pdf)
* [TIC 3.0 - Traditional TIC Use Case](https://www.cisa.gov/sites/default/files/publications/CISA%2520TIC%25203.0%2520Traditional%2520TIC%2520Use%2520Case.pdf)
