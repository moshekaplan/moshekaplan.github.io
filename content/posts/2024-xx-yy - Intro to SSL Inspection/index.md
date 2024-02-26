---
title: "Intro to SSL Inspection"
date: 2024-02-28T08:00:00-04:00
draft: true
---

# Why does SSL exist?
* What is the problem with plaintext communication?
* How does SSL solve that problem? 

* Note that although I'll be referring to this technology as SSL inspection, it is the same for TLS.[^1]

[^1]: According to Tim Dierks, the entire renaming from SSL to TLS was part of a negotiation between Netscape and Microsoft so that it wouldn't look like the IETF was simply adopting Netscape's implementation. For more info, see https://tim.dierks.org/2014/05/security-standards-and-name-changes-in.html .

# How does SSL work?
* What is a certificate? 
* What is a certificate chain? 
* What is a certificate store? 

# What is SSL Inspection?
* SSL as a problem -> No visibility into web traffic for other security capabilities (IDS, DLP, URL Filtering, external devices like full PCAP or Zeek)
* SSL inspection as a solution 
* * How SSL inspection could work with the certificate and private key  
* * How SSL inspection often uses a signing cert from a custom CA to avoid MITM errors 
* * Note that this is only possible with a custom CA loaded in the cert store 

# SSL Inspection on Palo Alto firewalls 
* Decryption rules
* * Can’t use fields only available after decryption 
* Decryption profiles (TLS versions, ciphersuites, etc.) 
* Inbound inspection 
* Outbound inspection 
* * Why inbound and outbound need different approaches 

* Basic Rule Design
* * General outbound decryption rule
* * Bypasses above based on source or destination IP 
* * Bypasses based on domain
* ** SNI and cert subject as a concept, and how that allows domain-based bypasses 
* ** Performance concerns 

# SSL Inspection Challenges 
* Background: Need to replicate failures (expiration, invalid cert, invalid chain) - link to BH talk or other research

* PA certificate store is missing a certificate 
* * Users gets a warning page on their browser that the server’s certificate is untrusted, but error doesn’t manifest outside at home
* * Need to add missing certificates to the PA’s certificate store 

* Custom certificate stores (e.g., Python, Java, Firefox) 
* * Users will get an error that the certificate is untrusted 
* * Requires adding custom CA to that certificate store 
* * Certificate pinning as as special case

* Active vs passive MITM  for inbound inspection
* * When is it needed? RSA vs EC 
* * Significance: Missing intermediate cert can cause handshake issues 
Which mode of operation is used is not present in the decryption logs and can make a difference when the target server
 presents a full certificate chain, but the PA only has the leaf certificate, as the client might require the full chain be present. So if the PA only has the leaf cert and brokers the connection, it could cause problems when the client uses an ECC-based algorithm
 in the handshake, as the PA would then only present the leaf certificate, which would cause the connection to fail. 

* Missing intermediate certificate 
* * Browsers use AIA (Authority Information Access), but PA doesn’t support, so we’d need to load in leaf certificates, otherwise certificate will be marked as untrusted 

* TLS v1.3 challenges
* * esni and ech

# Implementing SSL inspection

* Determine policy requirements for what domains or categories of domains should be exempted (e.g., healthcare data in an environment subject to HIPAA)
* Determine whether your SSL inspection solution will be used as a technical control to block insecure SSL/TLS protocols or ciphersuites

* Create bypasses for known problematic sites, like those that use certificate pinning or client certificates
* Use other tools, like Zeek, to detect client certs in advance

* Implement monitoring to detect issues
* * Detect SSL inspected connections that failed due to client certificates
* * Detect SSL inspected connections that failed due to unsupported cipher suites

* If you used centralized package installs, preload your root certificate into your trust stores.
* * Java
* * Python
* * npm

* Implement decryption in small pieces!
* * To avoid breaking too much at a time
* * To ensure resource utilization isn't a problem
