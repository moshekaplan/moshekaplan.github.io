---
title: "Inspecting an Android App's Web Traffic with HTTPS and Cert Pinning"
date:  2025-07-21T21:00:00-04:00
draft: false
---

One of the company's I interact with uses an online platform to share photos and videos. The platform has both a website and an Android app. However, the website only displays low-quality thumbnails while the app displays higher-quality photos. I wanted to download the higher-quality pictures, in bulk. To do that, I need to examine the underlying API requests so I can mimic them. How can I examine the app's web requests so I can download the higher-quality photos from my PC?

This article goes through how I was able to create a virtual Android device and inspect an Android app's encrypted web requests, even though the app used HTTPS with certificate pinning, so that I was able to examine the unencrypted web requests.

# Concept of Operation

On my desktop computer, if I wanted to examine how a website operated, I would use something like [Chrome Dev Tools](https://developer.chrome.com/docs/devtools/overview) to inspect all of the web requests involved in loading a webpage. However, Android apps don't come with something like that. So I need some way to be able to view all of the app's web requests and responses.

# Proxying through Burp Suite

[Burp Suite](https://portswigger.net/burp) is well known for its Burp Proxy, a web proxy which allows full visibility and even interception and modification of web requests. My first idea was to configure my phone to send all of the app's web requests through Burp Proxy, so that I could examine the requests and responses. Here are the steps involved:

1. Installed and launched Burp Suite
2. Set the proxy to listen on all interfaces, so it would be reachable from my phone (`Settings` -> `Tools` -> `Proxy`, and under `Proxy listeners`, select `Edit`, and then `All interfaces`)
3. Export Burp's CA certificate (Click `Import / export CA certificate`) for loading into my phone's certificate store
4. Transfer the Burp CA certificate to my phone (e.g., via Google Drive or USB file transfer)
5. Import the Burp CA certificate into my phone (`Settings` -> `Security and Privacy` -> `Other Security Settings` -> `Install from device storage` -> `CA certificate`). This is needed so HTTPS requests won't have a certificate error.
6. Under Wifi settings, select the relevant Wifi network, and under `Proxy`, select `Manual` and enter the PC's IP address and port `8080` (Burp's default proxy port)

![Image](<0. Burp Suite listen all interfaces.png> "Burp Suite Proxy listening on all interfaces")

OK, so now let's test this! First let's open Chrome to http://neverssl.com/, a website which specifically does not use HTTPS and so we should have full visibility into. And success!

![Image](<1. Burp Suite for neverssl.png> "Inspecting neverssl.com")

Now let's try another website in Chrome, this time using `https`, like https://example.com. And it worked too!

![Image](<2. Burp Suite for example.com.png> "Inspecting example.com")

So for our final step: Let's try opening the app:

![Image](<3. App error.jpg> "App error")

Hmm, that doesn't look right. And the Burp Proxy doesn't have any entries either. What's going on? Let's flip back to Burp's dashboard and see if there's anything interesting in the `Event log`:

![Image](<4. Failed SSL handshake.png> "Failed SSL handshake")

As you can see in the `Event detail`, `The client failed to negotiate a TLS connection to .... : Received fatal alert: certificate_unknown`, the app didn't like Burp's certificate. But we added the Burp certificate to our certificate store! Why is the app complaining about Burp's certificate?

The issue is that some applications *pin* a specific certificate and require that it be used. If any other certificate is used, the certificate validation (and so therefore, the HTTPS connection) fail. So now our problem is a little harder: We need to modify the application so that it allows the HTTPS connection to complete using Burp's certificate.

We can do this using a tool called Frida. According to its [website](https://frida.re/), Frida is a toolkit which makes it possible to:
> Inject your own scripts into black box processes. Hook any function, spy on crypto APIs or trace private application code, no source code needed. Edit, hit save, and instantly see the results. All without compilation steps or program restarts.

However, Frida requires either rooting the Android device or repackaging the app. I don't want to root my device and repackaging an app sounds pretty laborious. So instead, I decided to create a virtual Android device with root access instead.

# Windows Subsystem for Android

To create a virtual Android device, I decided to use [Windows Subsystem for Android (WSA)](https://learn.microsoft.com/en-us/previous-versions/windows/android/wsa/), a now-unsupported[^wsa_unsupported] capability from Microsoft which enables Windows 11 PCs to run Android apps. Setting up WSA was fairly straightforward:

[^wsa_unsupported]: From https://learn.microsoft.com/en-us/previous-versions/windows/android/wsa/: "Starting March 5, 2025, Windows Subsystem for Android™ and the Amazon Appstore are no longer available in the Microsoft Store."

1. In `Turn Windows features on and off` enable the following:
    * Hyper-V
    * Virtual Machine Platform
    * Windows Hypervisor Platform
    * Windows Subsystem for Linux
2. Restart the PC.
3. Download a pre-built WSA from https://github.com/MustardChef/WSABuilds/releases/tag/Windows_11_2407.40000.4.0_LTS_7. I specifically wanted Google Apps (for the Play Store) + magisk (root access), so I downloaded 
https://github.com/MustardChef/WSABuilds/releases/download/Windows_11_2407.40000.4.0_LTS_7/WSA_2407.40000.4.0_x64_Release-Nightly-with-magisk-29.0.29000.-stable-GApps-13.0.7z
4. Unzip the pre-built WSA files to `C:\wsa`, so that the file path is not too long.
5. Install the image by clicking `Run.bat`. After it completes, there will now be new start menu options for the Android apps.
6. I opened the "Google app" from my start menu and logged into a Google account, so I would have access to the Play Store
7. Then I opened the Play Store and installed the app of interest.

# Installing Frida with magisk

Now that I had an Android running in the WSA, I needed to install Frida in it. I had found a [magisk-frida](https://github.com/ViRb3/magisk-frida) module, but Magisk only supports loading 'modules' from the device, so how do I transfer the files to the WSA in the first place?

The easiest approach was to share a folder from my PC to the WSA. In the Windows Subsystem for Android "app", under "Advanced Settings":
* Enabled `Developer mode`
* Enabled `Share User folders`

![Image](<5. Shared Folders.png> "Enabling Share User Folders.png")

Now that you have the Shared Folder setup, you can:
1. Download the newest [magisk-frida release](https://github.com/ViRb3/magisk-frida/releases/) 
2. Copy the zipfile to the shared folder 
3. Install the module with magisk by:
    1. Opening magisk, 
    2. Going to `Modules`, 
    3. Clicking `Install from Storage`, 
    4. Opening the hamburger menu from the top-left and selecting `Subsystem for Android (TM)`,
    5. Clicking on the `Windows` folder, and selecting the magisk-frida zip file (e.g., `MagiskFrida-17.2.12-1.zip`), and
    6. Clicking `OK` on the `Install Confirmation` pop-up.

To confirm that installation is operational, install Frida on your pc with `pip install frida-tools` and run `frida-ps -U` on your PC to confirm that you can connect to the virtual Android device's Frida server and view the list of running programs.


# Installing Frida manually

If for whatever reason you're unable to install Frida with magisk, you can also install Frida manually. 

1. Download `adb` from Android's platform tools: https://developer.android.com/tools/releases/platform-tools
2. Connect to the WSA with: `adb connect 127.0.0.1:58526`
3. Check your architecture with: `adb shell getprop ro.product.cpu.abilist`. Mine were: `x86_64,arm64-v8a,x86,armeabi-v7a,armeabi`
4. Launch a root shell by running `adb shell` and `su`
5. Approve the escalation to root within the Magisk app.
6. Assuming you're also running on a 64-bit system, download `frida-server-17.2.12-android-x86_64` (or newer) from https://github.com/frida/frida/releases , unzip it to your shared files, and rename it to `frida-server`.
7. Access the shared files from your adb shell: `cd /mnt/user/0/self/primary/Windows/`
8. Run frida-server: `chmod 755 frida-server` and `frida-server &`
9. As a final step, install Frida on your pc with `pip install frida-tools` and run `frida-ps -U` on your PC to confirm that you can connect to the frida server and view the list of running programs.

For more details, see https://frida.re/docs/android/

# Bypassing Certificate Pinning

Now that we have `frida-server` running, we now need to inject code into the app so that it will bypass the certificate pinning.

I've never written Frida code, but I fortunately found the HTTP Tookit's: *Frida Mobile Interception Scripts* available at https://github.com/httptoolkit/frida-interception-and-unpinning 

Their ["Android Getting Started Guide"](https://github.com/httptoolkit/frida-interception-and-unpinning?tab=readme-ov-file#android-getting-started-guide) is pretty clear, but in short, open `config.js` and:
* set the `CERT_PEM` to your Burp certificate in PEM format,
* `PROXY_HOST` to your PC's IP, and 
* `PROXY_PORT` to the port Burp is lstening on (default of `8080`)

Then copy over the entire directory to your WSA.

The next step is to get the app's identifier. You can get the list of installed app's by running Frida on your PC with `frida-ps -Uai`.

```bash
> frida-ps -Uai
 PID  Name                                     Identifier
----  ---------------------------------------  ---------------------------------------
7666  Amazon Appstore                          com.amazon.venezia
   -  Files                                    com.android.documentsui
   -  Google                                   com.google.android.googlequicksearchbox
   -  Google                                   com.google.android.googlequicksearchbox
   -  Google Play Store                        com.android.vending
   -  Magisk                                   com.topjohnwu.magisk
   -  Windows Subsystem for Android™ Camera    com.android.camera2
   -  Windows Subsystem for Android™ Contacts  com.android.contacts
   -  Windows Subsystem for Android™ Gallery   com.android.gallery3d
   -  Windows Subsystem for Android™ Settings  com.android.settings
```

As an example, you can see that the `Amazon Appstore` has an `Identifier` of `com.amazon.venezia`.

Now that we finally have everything we need, let's use Frida to bypass the certificate pinning!

On your PC, run the command below, replacing `<app identifier>` with the `Identifier` obtained by running `frida-ps -Uai`:

`frida -U -l ./config.js -l ./native-connect-hook.js -l ./native-tls-hook.js -l ./android/android-proxy-override.js -l ./android/android-system-certificate-injection.js -l ./android/android-certificate-unpinning.js -l ./android/android-certificate-unpinning-fallback.js -l ./android/android-disable-root-detection.js -f <app identifier>`

This will launch the app. Now we can try replicating the action in the app and check the request and success! We are no longer getting HTTPS connection failures and can see the web request in plaintext in Burp:

![Image](<6. Final - success.png> "Success!")

# Final thoughts

The analysis of the web requests was the simplest part and I was able to write a Python script to download my photos with a higher resolution! However I am intentionally omitting identifying details of the app here due to some minor security issues I noticed while examining the web requests.

Embarassingly, once I started examining the app's web requests, I realized that the website was calling the exact same APIs, only that it was programmed to only display the lower-quality thumbnails. Therefore, analzying the website's requests would have gotten me to the same place without needing to set up a virtual Android device with WSA and Frida. No regrets though, as this was a fun project and I finally got to use Frida!

And next time?[^objection_broken] Maybe I'll try repeating this with [objection](https://github.com/sensepost/objection)'s [android sslpinning disable](https://github.com/sensepost/objection/blob/master/objection/console/helpfiles/android.sslpinning.disable.txt), as described [here](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0012/#bypassing-methods).

[^objection_broken]: Can't do it now because it's currently broken, see: https://github.com/frida/frida/issues/3460

# References and further reading
* Google.com: Add & remove certificates https://support.google.com/pixelphone/answer/2844832?hl=en
* Frida - Android: https://frida.re/docs/android/
* Defeating Android Certificate Pinning with Frida: https://httptoolkit.com/blog/frida-certificate-pinning/
* magisk-frida troubleshooting: https://github.com/ViRb3/magisk-frida/blob/master/TROUBLESHOOTING.md
* MustardChef WSA - Fix Virtualization Error: https://github.com/MustardChef/WSABuilds/blob/master/MagiskOnWSA/docs/Fixes/FixVirtError.md
* WSA Sideloader - https://github.com/MustardChef/WSABuilds/blob/master/Documentation/Usage%20Guides/Sideloading%20Guides/WSA-Sideloader.md
* "INSTALL Google Play Store on Windows 11 🚀🤯 Super Easy and Without Emulators 2025" - https://www.youtube.com/watch?v=9z2Vz53pdqw
* "MASTG-TECH-0012: Bypassing Certificate Pinning" - https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0012/
* SSL Pinning Bypass for Android using Frida: https://redfoxsec.com/blog/ssl-pinning-bypass-android-frida/
* Frida CodeShare - Project: Universal Android SSL Pinning Bypass with Frida
: https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/
* GitHub - Frida Mobile Interception Scripts: https://github.com/httptoolkit/frida-interception-and-unpinning

