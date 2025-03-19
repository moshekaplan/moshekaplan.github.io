---
title: "Getting Started with Apparmor, starring Aircrack-ng"
date: 2015-07-17T08:00:00-04:00
draft: false
---

This post will go over how I created AppArmor profiles for two of the most well-known programs in the aircrack-ng suite of tools, aircrack-ng  and airodump-ng .

# Installing AppArmor

AppArmor is installed by default on Ubuntu. What we'll need is the apparmor-utils  package, which contains the utilities to simplify creating new AppArmor policies. Installing that is as easy as running:

sudo apt-get install apparmor-utils

# Creating your first profile  aircrack-ng

We could start with an empty profile, and then refining that until it works. Or we could make our life easier by using aa-genprof, short for AppArmor generate profile, which does the following:

1. Loads an empty policy and puts it into WARN mode
1. (The user runs the program, trying to exercise as much functionality as possible)
1. Scans the log for warnings, and generates a profile based on those policy violations
1. Sets the policy to enforce.

So let's start with running aa-genprof :

`sudo aa-genprof <path/to/binary>`

or even:

`sudo aa-genprof <binary>`

I started with making a profile for aircrack-ng, which takes a PCAP file and attempts to crack the wireless password. It's a simple program to write a profile for, because of its very focused capabilities. So let's get started:

```
moshe@moshe-desktop:~/Desktop/aircrack/src$ sudo aa-genprof aircrack-ng
Writing updated profile for /home/moshe/Desktop/aircrack/src/aircrack-ng.
Setting /home/moshe/Desktop/aircrack/src/aircrack-ng to complain mode.

Before you begin, you may wish to check if a
profile already exists for the application you
wish to confine. See the following wiki page for
more information:
http://wiki.apparmor.net/index.php/Profiles

Please start the application to be profiled in
another window and exercise its functionality now.

Once completed, select the "Scan" option below in 
order to scan the system logs for AppArmor events. 

For each AppArmor event, you will be given the 
opportunity to choose whether the access should be 
allowed or denied.

Profiling: /home/moshe/Desktop/aircrack/src/aircrack-ng

[(S)can system log for AppArmor events] / (F)inish
```

You can run the program a few times, to attempt to trigger as the program's full functionality. I ran make check and realizing that the test files don't use the -l  switch (which writes the output to a file), also executed the following to test -l:

```
aircrack-ng  ../test/wep\_64\_ptw.cap -l output\_from\_test
```

Switching back to the terminal running aa-genprof  and hitting S:

```
Reading log entries from /var/log/audit/audit.log.
Updating AppArmor profiles in /etc/apparmor.d.
Complain-mode changes:

Profile:  /home/moshe/Desktop/aircrack/src/aircrack-ng
Path:     /home/moshe/Desktop/aircrack/test/password.lst
Mode:     r
Severity: 4

  1 - /home/moshe/Desktop/aircrack/test/password.lst 
 [2 - /home/*/Desktop/aircrack/test/password.lst]
[(A)llow] / (D)eny / (I)gnore / (G)lob / Glob with (E)xtension / (N)ew / Abo(r)t / (F)inish / (M)ore
```

For now, let's just hit A' to allow all of these and then hit F' to save the profile.

Let's open the generated profile in an editor and see if we can clean it up. The generated profile is stored with all of the other AppArmor profiles, in `/etc/apparmor.d/` as  `home.moshe.Desktop.aircrack.src.aircrack-ng`. Here's what it contains:

```
# Last Modified: Sun Jul 19 12:27:36 2015
#include <tunables/global>

/home/moshe/Desktop/aircrack/src/aircrack-ng {
#include <abstractions/base>

/home/*/Desktop/aircrack/src/output_from_test w,
/home/*/Desktop/aircrack/test/password.lst r,
/home/*/Desktop/aircrack/test/wep_64_ptw.cap r,
/home/*/Desktop/aircrack/test/wpa-psk-linksys.cap r,
/home/*/Desktop/aircrack/test/wpa.cap r,
/home/*/Desktop/aircrack/test/wpa2-psk-linksys.cap r,
/home/*/Desktop/aircrack/test/wpa2.eapol.cap r,
/home/moshe/Desktop/aircrack/src/aircrack-ng mr,
}
```


So let's review the generated profile:

\*  is a wildcard, and includes any file or directory

The letter at the end of the line is the mode allowed for that file. This profile uses: ***r**ead*, ***w**rite*, and ***m**emory map*,

Now, aircrack-ng needs to be able to read a pcap from anywhere the user specifies. At the same time, we don't want to allow aircrack-ng to access places where the user definitely doesn't have a pcap file. So let's replace all those read permissions with a single wildcard to allow reading any file inside of the user's home directory:

```
/home/moshe/Desktop/aircrack/src/aircrack-ng {
#include <abstractions/base>

/home/*/Desktop/aircrack/src/output_from_test w,
/home/** r,
/home/moshe/Desktop/aircrack/src/aircrack-ng mr,
}
```


OK, that's a lot smaller now. Let's also allow aircrack-ng  to write the key to any file in the home directory  that should be enough for most users:

```
#include <tunables/global>

/home/moshe/Desktop/aircrack/src/aircrack-ng {
  #include <abstractions/base>

  /home/** w,
  /home/** r,
  /home/moshe/Desktop/aircrack/src/aircrack-ng mr,
}
```

Now, one issue with allowing reading and writing everywhere in /home   there are lots of files that shouldn't be able to be overwritten, like the dot files (.ssh, for example). Let's restrict those with a deny  rule:

```
#include <tunables/global>

/home/moshe/Desktop/aircrack/src/aircrack-ng {
  #include <abstractions/base>

  # No need to access dot files
  deny /home/*/.** rw,

  /home/** w,
  /home/** r,
  /home/moshe/Desktop/aircrack/src/aircrack-ng mr,
}
```

The deny rule is processed first, so aircrack-ng can now write anywhere in the home directory, as long as it isn't a dot file.

A detail to think about is that not all users have their home as /home/<username>. For example, root's home directory is in /root. Luckily for us, there's a predefined variable that includes all locations for home: @{HOME}. Let's modify our policy to use that variable instead:

```
#include <tunables/global>

/home/moshe/Desktop/aircrack/src/aircrack-ng {
  #include <abstractions/base>

  # No need to access dot files
  deny @{HOME}/.** rw,

  @{HOME}/** w,
  @{HOME}/** r,
  @{HOME}/moshe/Desktop/aircrack/src/aircrack-ng mr,
}
```

We also have another protection available: The owner  keyword, which only allows the permission if they are the owner of the file. The owner keyword is especially useful when running programs that need root permissions, to prevent them from overwriting other user's files. aircrack-ng doesn't need root, but as a good habit, let's only allow aircrack-ng to overwrite files belonging to the owner, to prevent a malicious aircrack-ng from overwriting any other user's files:

```
#include <tunables/global>

/home/moshe/Desktop/aircrack/src/aircrack-ng {
  #include <abstractions/base>

  # No need to access dot files
  deny @{HOME}/.** rw,

  owner @{HOME}/** w,
  @{HOME}/** r,
  @{HOME}/moshe/Desktop/aircrack/src/aircrack-ng mr,
}
```

Another item of interest is the predefined abstraction private-files-strict. What that does is prevent access to sensitive files, which are mostly dotfiles, but may include other items in the future.

The last entry in the profile, /home/moshe/Desktop/aircrack/src/aircrack-ng mr , is required for core dumps. We'll keep that permission as-is, but fix the path. aa-genprofile  uses the current location of the binary, but that isn't where aircrack will be when you install it with your package manager.

```
#include <tunables/global>

/usr/bin/aircrack-ng {
  #include <abstractions/base>
  #include <abstractions/private-files-strict>

  # No need to access dot files
  deny @{HOME}/.** rw,

  owner @{HOME}/** w,
  @{HOME}/** r,
 /usr/bin/aircrack-ng mr,
}
```


Don't forget to also rename the apparmor policy file to usr.bin.aircrack-ng  !

Now we have a nice simple profile that limits aircrack-ng to reading and writing files. Even if a malicious pcap file would exploit a vulnerability in aircrack-ng that causes it to execute the attacker's code, they'd be extremely limited in what they could do, and would (hopefully) not be able to cause any real harm.

# Creating a second profile  airodump-ng

This time, we're going to write a profile for airodump-ng , which opens an interface in monitor mode and dumps the raw packets into a file. airodump-ng  would greatly benefit from an AppArmor profile, as it needs to run as root to obtain the raw packets.

Let's start with the same steps as before, running aa-genprof airodump-n (with all of these commands run as root) :

```
airmon-ng start wlan0
aa-genprof airodump-ng
```


And in another terminal:

```
./airodump-ng -w outfile_test1 mon0
./airodump-ng -w outfile_test2 --output-format pcap mon0
./airodump-ng -w outfile_test3 --output-format ivs mon0
./airodump-ng -w outfile_test4 --output-format csv mon0
./airodump-ng -w outfile_test5 --output-format gps mon0
./airodump-ng -w outfile_test6 --output-format kismet mon0
./airodump-ng -w outfile_test7 --output-format netxml mon0
./airodump-ng -w outfile_test8  --manufacturer mon0
./airodump-ng -w outfile_test9  --gpsd mon0
./airodump-ng -r outfile_test1-01.cap -w outfile_test10
```


Switching back to the original terminal, hit S' to scan the system log for AppArmor events.

I accepted the first few events it captured, to allow the required capabilities. Now we reached one of the file entries:

```
Profile: /home/moshe/Desktop/aircrack/src/airodump-ng
Path: /home/moshe/Desktop/aircrack/src/outfile_test1-01.cap
Mode: r
Severity: 4

 1 - /home/moshe/Desktop/aircrack/src/outfile_test1-01.cap 
 [2 - /home/*/Desktop/aircrack/src/outfile_test1-01.cap]
[(A)llow] / (D)eny / (I)gnore / (G)lob / Glob with (E)xtension / (N)ew / Abo(r)t / (F)inish / (M)ore

Profile: /home/moshe/Desktop/aircrack/src/airodump-ng
Path: /home/moshe/Desktop/aircrack/src/outfile_test1-01.cap
Mode: r
Severity: 4
```

Glob with (E)xtension keeps the extension the same, but globs the source file. Let's hit E' a few times, so it covers everything in the home directory and then allow it:

```
Profile: /home/moshe/Desktop/aircrack/src/airodump-ng
Path: /home/moshe/Desktop/aircrack/src/outfile_test1-01.cap
Mode: r
Severity: 4

 1 - /home/moshe/Desktop/aircrack/src/outfile_test1-01.cap 
 2 - /home/*/Desktop/aircrack/src/outfile_test1-01.cap 
 3 - /home/*/Desktop/aircrack/src/*.cap 
 4 - /home/*/Desktop/aircrack/**.cap 
 5 - /home/*/Desktop/**.cap 
 [6 - /home/*/**.cap]
[(A)llow] / (D)eny / (I)gnore / (G)lob / Glob with (E)xtension / (N)ew / Abo(r)t / (F)inish / (M)ore
Adding /home/*/**.cap r to profile
```

What's great about globbing is that it'll detect which files are already included, and not display those to us again.

So, let's examine the generated profile:

```
# Last Modified: Wed Aug 26 19:26:58 2015
#include <tunables/global>

/home/moshe/Desktop/aircrack/src/airodump-ng {
 #include <abstractions/base>
 #include <abstractions/nameservice>


 capability dac_override,
 capability net_admin,
 capability net_raw,
 capability setuid,
 capability sys_module,

 network packet raw,

 /bin/dash r,
 /bin/ls r,
 /home/**.cap rw,
 /home/*/**.csv rw,
 /home/*/**.gps rw,
 /home/*/**.ivs rw,
 /home/*/**.kismet.netxml rw,
 /home/moshe/Desktop/aircrack/src/airodump-ng mr,
 /proc/*/net/psched r,
 /proc/acpi/ac_adapter/ r,
 /proc/acpi/battery/ r,
 /sbin/ r,
 /sbin/iwpriv r,
 /usr/share/aircrack-ng/airodump-ng-oui.txt r,
}
```

So let's do our basic fixes:

- Fix the path to airodump-ng
- Use the predefined variable for home
- Add the private-files-strict abstraction and deny access to dotfiles
- Add the owner tag for any file access
- Add some spacing for readability

```
#include <tunables/global>

/usr/sbin/airodump-ng {
 #include <abstractions/base>
 #include <abstractions/nameservice>
 #include <abstractions/private-files-strict>

 /usr/sbin/airodump-ng mr, 
 capability dac_override,
 capability net_admin,
 capability net_raw,
 capability setuid,
 capability sys_module,

 network packet raw,

 # No need to access dot files
 deny @{HOME}/.** rw, 
 /bin/dash r,
 /bin/ls r,

 owner @{HOME}/**.cap rw,
 owner @{HOME}/**.csv rw,
 owner @{HOME}/**.gps rw,
 owner @{HOME}/**.ivs rw,
 owner @{HOME}/**.kismet.netxml rw,

 /proc/*/net/psched r,
 /proc/acpi/ac_adapter/ r,
 /proc/acpi/battery/ r,

 /sbin/ r,
 /sbin/iwpriv r,

 /usr/share/aircrack-ng/airodump-ng-oui.txt r,
}
```

Hmm, `/bin/dash` is awfully specific. What is someone has a different shell, like `zsh`,`ksh`, or plain old `sh`? Let's replace `/bin/dash` with `/bin/*sh`  to cover all of those possibilities. This may end up including other programs, but this is a tradeoff we need to make, as we need our profile to work for users, independent of the shell they use.

```
#include <tunables/global>

/usr/sbin/airodump-ng {
 #include <abstractions/base>
 #include <abstractions/nameservice>
 #include <abstractions/private-files-strict>

 /usr/sbin/airodump-ng mr, 
 capability dac_override,
 capability net_admin,
 capability net_raw,
 capability setuid,
 capability sys_module,

 network packet raw,

 # No need to access dot files
 deny @{HOME}/.** rw, 

 /bin/*sh r,
 /bin/ls r,

 owner @{HOME}/**.cap rw,
 owner @{HOME}/**.csv rw,
 owner @{HOME}/**.gps rw,
 owner @{HOME}/**.ivs rw,
 owner @{HOME}/**.kismet.netxml rw,

 /proc/*/net/psched r,
 /proc/acpi/ac_adapter/ r,
 /proc/acpi/battery/ r,

 /sbin/ r,
 /sbin/iwpriv r,

 /usr/share/aircrack-ng/airodump-ng-oui.txt r,
}
```

This profile is strange. Why would airodump-ng  want to *read* programs like ls , iwpriv , and a shell? Wouldn't it need to *execute* them?

After `aa-genprof` completes, it puts the generated policy in enforce mode. Let's try running airodump-ng again, and see if there are any policy violations:

```
sudo ./airodump-ng -i wlan0mon
sudo aa-logprof
```

Ahah!

```
moshe@moshe-desktop:~$ sudo aa-logprof 
Reading log entries from /var/log/audit/audit.log.
Updating AppArmor profiles in /etc/apparmor.d.

Profile:  /home/moshe/Desktop/aircrack/src/airodump-ng
Execute:  /sbin/iwpriv
Severity: unknown

(I)nherit / (C)hild / (P)rofile / (N)amed / (U)nconfined / (X) ix On / (D)eny / Abo(r)t / (F)inish
```

A brief intro to executable permissions:

- *Inherit* allows the program to execute with the same permissions as the program that launches it.
- *Child* requires that the program use a sub-profile declared within the main program's profile. More on this soon.
- *Unconfined* allows the program to execute freely. This is a bad idea.

Generally speaking, an *inherit* profile could be used if there's a large amount of overlap in capabilities, but my opinion is that you'd be far better served using a custom *child profile* whenever possible. At a minimum, you should write a child profile for any program that requires internet access or does complex parsing.

The option we'll select is C', to create a c*hild* profile for the program.

Now we get our next question:

```
Should AppArmor sanitise the environment when
switching profiles?

Sanitising environment is more secure,
but some applications depend on the presence
of LD_PRELOAD or LD_LIBRARY_PATH.

(Y)es / [(N)o]
```

A sanitized environment is the safer option, as it prevents any attacks made possible by environment variables (like LD\_PRELOAD). Let's use that here.

Now let's accept the rest of the additions, using child profiles with sanitized environments.

```
#include <tunables/global>

/usr/sbin/airodump-ng {
 #include <abstractions/base>
 #include <abstractions/nameservice>
 #include <abstractions/private-files-strict>

 /usr/sbin/airodump-ng mr,

 capability dac_override,
 capability net_admin,
 capability net_raw,
 capability setuid,
 capability sys_module,

 network packet raw,

 # No need to access dot files
 deny @{HOME}/.** rw,

 /bin/*sh rCx,
 profile /bin/*sh{
   #include <abstractions/base>

   /bin/*sh mr,
   /bin/ls rix,
   /proc/filesystems r,
   /sys/class/ieee80211/ r,
 }

 owner @{HOME}/**.cap rw,
 owner @{HOME}/**.csv rw,
 owner @{HOME}/**.gps rw,
 owner @{HOME}/**.ivs rw,
 owner @{HOME}/**.kismet.netxml rw,

 /proc/*/net/psched r,
 /proc/acpi/ac_adapter/ r,
 /proc/acpi/battery/ r,

 /sbin/ r,
 /sbin/iwpriv r,

 profile /sbin/iwpriv{
   #include <abstractions/base>
   network inet dgram,

   /sbin/iwpriv mr,
 }

 /usr/share/aircrack-ng/airodump-ng-oui.txt r,
}
```

That's it! We're done!

# When things go wrong:

While writing a profile, a few things can (and will) go wrong. The first thing to check when loading a profile is that there are no parser errors. If apparmor can't parse and load the profile, it can't enforce it.

So when there are problems, use the included tools:

- `aa-complain <path/to/binary>` to log every policy violation.
- `sudo invoke-rc.d apparmor reload` to reload all of the policies
- `sudo apparmor\_parser -r /etc/apparmor.d/path.to.binary` to reload a single policy
- `sudo aa-status` to make sure that your policy is loaded and in the correct mode.
- `sudo aa-logprof` to see if there are any new policy violations
- `tail /var/log/syslog` to view the system log, to see which policy violations occurred

# Final thoughts:

AppArmor is a useful tool for constraining a program's capabilities, to limit the damage if it were exploited. Some programs are harder to write profiles for than others. But if you plan on exposing any service to the Internet, it would be wise to consider enabling an AppArmor profile.

There's plenty of debate if AppArmor is better or worse than SELinux. In either case, I'd rather have an imperfect AppArmor profile than no profile at all. AppArmor's integration into Ubuntu also makes it an excellent place to start.

Shout out to cboltz and sarnold of the AppArmor team for answering a ton of questions in IRC.

Also, certain topics were completely skipped including hats and other supported execution modes. This was intentional, as the post was long enough.

The profiles developed in the post (along with several other AppArmor profiles) are available in the [aircrack-ng svn repository](https://trac.aircrack-ng.org/browser/trunk/apparmor/). If you have any further suggestions on how they could be improved, please let me know.

Moshe

# References and further reading:

* http://askubuntu.com/questions/236381/what-is-apparmor
* http://wiki.apparmor.net/index.php/QuickProfileLanguage

