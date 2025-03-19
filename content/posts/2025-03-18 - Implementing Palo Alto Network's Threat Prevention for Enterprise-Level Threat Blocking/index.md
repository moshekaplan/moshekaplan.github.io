---
title: "Implementing Palo Alto Network's Threat Prevention for Enterprise-Level Threat Blocking"
date: 2025-03-18T08:00:00-04:00
draft: false
---

Network Intrusion detection systems have been around for decades. However, going from intrusion _detection_ to intrusion _prevention_ can be scary because false positives can break production systems. In this writeup, I describe how I was able to deploy Palo Alto Network's threat prevention in blocking mode in an enterprise environment to help us move our network security closer to zero-trust. I am also publishing the [Python script](https://github.com/moshekaplan/palo_alto_firewall_scripts/blob/main/threat_prevention_hardening.py) used to make the bulk firewall changes and create the spreadsheet for analyzing threat alerts.

# What is Palo Alto Networks Threat Prevention?

Network IDS and IPS have historically been implemented at the network perimeter. However, that means that if someone is able to get past the perimeter's security controls, they have unfettered access to all internal systems. Palo Alto Networks (PAN) firewalls work a little differently. Instead of implementing network IDS/IPS as a separate system at the network perimeter, the Network IDS/IPS capabilities (known as *Threat Prevention*) are managed per-firewall rule and so we can have security controls enabled for every single network flow that goes through the firewall.

PAN firewalls Threat Prevention licensing consists of [Antivirus, Anti-spyware, and Vulnerability Protection](https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-admin/subscriptions/all-subscriptions). As described in [PAN's docs](https://docs.paloaltonetworks.com/network-security/security-policy/administration/security-profiles):

> - [Antivirus](https://docs.paloaltonetworks.com/content/techdocs/en_US/network-security/security-policy/administration/security-profiles/security-profile-antivirus.html) and [Anti-Spyware](https://docs.paloaltonetworks.com/content/techdocs/en_US/network-security/security-policy/administration/security-profiles/security-profile-anti-spyware.html) profiles are designed to detect and prevent malicious software and spyware from infiltrating the network. They scan traffic for known and unknown threats, employing signature-based and behavior-based detection mechanisms to swiftly respond and mitigate potential security breaches.
> - [Vulnerability Protection](https://docs.paloaltonetworks.com/content/techdocs/en_US/network-security/security-policy/administration/security-profiles/security-profile-vulnerability-protection.html) profiles focus on identifying and blocking exploits and vulnerabilities that bad actors might attempt to leverage. These profiles proactively safeguard systems and applications from potential weaknesses that cybercriminals exploit to compromise networks.
> - [URL Filtering](https://docs.paloaltonetworks.com/content/techdocs/en_US/network-security/security-policy/administration/security-profiles/security-profile-url-filtering.html) profiles let you manage and control user access to websites and web applications. They classify URLs based on predefined categories, allowing you to enforce Security policies and reduce exposure to risky sites.

Closely related are also File Blocking and Data Filtering profiles:

> - [File Blocking](https://docs.paloaltonetworks.com/content/techdocs/en_US/network-security/security-policy/administration/security-profiles/security-profile-file-blocking.html) profiles monitor and regulate the types of files transferred through the network, helping prevent the dissemination of malicious or unwanted file types. By restricting or blocking certain file extensions or content types, you can minimize the risk of malware propagation.
> - [Data Filtering](https://docs.paloaltonetworks.com/content/techdocs/en_US/network-security/security-policy/administration/security-profiles/security-profile-data-filtering.html) profiles, also known as data loss prevention (DLP) profiles, focus on protecting sensitive data by identifying and controlling its transmission. These profiles ensure that confidential information, such as credit card numbers or social security numbers, isn't inadvertently leaked or accessed by unauthorized parties.

To enable each of these capabilities, you need to create a *Profile* for each capability and then assign it to the relevant firewall rules. Attaching the same collection of profiles over and over gets old quick, so the PAN firewall supports creating *[Security Profile Groups](https://docs.paloaltonetworks.com/pan-os/11-2/pan-os-web-interface-help/objects/objects-security-profile-groups)*, which are collections of profiles for each threat prevention capability which can be assigned to a rule as a single unit .

# Planning Threat Prevention Implementation

In an ideal world, we'd create threat prevention capabilities based on PAN's best practices, assign it to all rules, and we'd mark the effort complete. However, this lofty goal is not so easy - the threat prevention capabilities can have false positives which could cause an outage in your production systems.

PAN provides some [guidance](https://docs.paloaltonetworks.com/best-practices/internet-gateway-best-practices/best-practice-internet-gateway-security-policy/transition-safely-to-best-practice-security-profiles) as to how to transition the profiles to blocking mode, but it not concrete enough to implement and was extremely manual. So let's come up with our own plan:


1. Design an ideal end-state
1. Collect threat prevention alert data
1. Analyze threat prevention data
1. Attach secure security profile groups to firewall rules

Of course, the devil is in the details. So let's delve into each step.

# Design an ideal end-state

As a starting point, we can define our goal as to roughly mimic PAN's [recommendations](https://docs.paloaltonetworks.com/best-practices/internet-gateway-best-practices/best-practice-internet-gateway-security-policy/create-best-practice-security-profiles), which can be roughly summarized as the following:  

- **Antivirus**: Enabling blocking (action of "reset-both") for all supported protocols
- **Anti-spyware**: Set action to "reset-both" for medium, high, and critical threats and "sinkhole" for all DNS Policies
- **Vulnerability Protection**: Set action to "reset-both" for medium, high, and critical threats
- **URL Filtering**: Block all malicious URL categories
- **File Blocking**: Block risky file types

Note that for this article, we don't focus on Data Filtering profiles, because they are too business-specific. However, similar approaches would work.

For URL filtering, PAN [recommends](https://docs.paloaltonetworks.com/best-practices/internet-gateway-best-practices/best-practice-internet-gateway-security-policy/create-best-practice-security-profiles) blocking the following malicious URL filtering categories:

> - **command-and-control** — URLs and domains that malware or compromised systems use to communicate with an attacker’s remote server.
> - **grayware** — These sites don’t meet the definition of a virus or pose a direct security threat, but they influence users to grant remote access or perform other unauthorized actions. Grayware sites include scams, illegal activities, criminal activities, adware, and other unwanted and unsolicited applications, including “typosquatting” domains.
> - **malware** — Sites known to host malware or used for command-and-control activities.
> - **phishing** — Sites known to host credential and personal information phishing pages, including technical support scams and scareware.
> - **ransomware** — Sites that are known to distribute ransomware.
> - **scanning-activity** — Sites that probe for existing vulnerabilities or conduct targeted attacks.

PAN has a recommended list of file types to include in File Blocking, but I caution against using their list. It is extremely broad and will almost certainly impact business operations. For the purposes of this article, we'll set our goal as blocking `scr` (Windows screensaver) files, but the approach is the same regardless of which file types you choose to block.

So now we have our first "secure" Security Profile Group: One with our ideal security profiles for Antivirus, Anti-spyware, Vulnerability Protection, URL Filtering, and File Blocking. For reference purposes, we'll name it `secure`.

However, we still have a few other use cases:  

* Vulnerability scanners are much more effective when they're not blocked by the firewall. They also generate a flood of alerts that are practically noise. To maintain their effectiveness, we'll need to either use profiles which only alert or set them to not even alert at all. For your own environment, you'll need to decide how to handle these. For reference purposes, we'll name this profile `Vulnerability Scanners`.

* Penetration testers also like being able to do their jobs. You might want to disable threat blocking (but keep alerting!) for approved penetration tester activity. For your own environment, you'll need to decide how to widely you'll enable these exceptions. For reference purposes, we'll name this profile `Penetration Testers`.

* For firewall rules allowing access to externally-facing webservers, a blocking URL Filtering profile doesn't make much sense, as any 'malicious' categorizations would be false positives and so enabling blocking would have only downside, with no upside. As such, we'd want to use a profile with the URL filtering actions set to "Alert". For reference purposes, we'll name it `secure - for webservers`.

* We're almost certainly going to need to create at least a few exceptions. Different rules will need different exceptions. In a perfect world, each exception would be perfectly scoped to the rule that needed it. However, that would result in an unmaintainable number of security profile groups. So instead, we need to strike a balance between how broadly we implement our exceptions and the number of security profile group's we're willing to manage. Some possibilities include grouping exceptions based on:

  - source zone
  - destination zone
  - system
  - inbound vs outbound

The good thing is that we don't need to decide on this now - we can wait until we have a better understanding of which rules will need exceptions before finalizing this decision.

# Collect threat prevention alert data

Now that we have a rough idea of what we are working towards, we can begin collecting data. Collecting data is thankfully easy - all we need to do is create a Security Profile Group in which all the threat prevention profiles are set to "Alert" and assign it to the rules where we want to collect data from. We'll refer to this security Profile Group as `Alert only`.

To ensure that all **new** firewall rules will also have alerting enabled for threat detection, you can clone the `Alert only` profile to create a new Security Profile Group named `default`. The PAN firewalls will then automatically assign the `default` Security Profile Group as the Security Profile Group for all newly-created policies. For more info, see [here](https://docs.paloaltonetworks.com/network-security/security-policy/administration/security-profiles/security-profile-groups).

One thing to note is that enabling threat prevention can significantly lower traffic throughput. My own limited testing indicated about a 50% throughput hit. If one of your systems regularly transfers very large files, you might want to run performance benchmarks before and after enabling threat prevention to ensure that the performance hit does not cause problems.

To ensure high-quality data, be sure that your time period is sufficiently long and contains any irregular activities like failover, load testing, and any recurring special events.

For this analysis, we'll also need traffic data, so please ensure that you have either "Log At Session Start" and "Log at Session End" enabled for every rule, together with a "Log Forwarding Profile" to send the logs to some sort of centralized system like Splunk or ElasticSearch.

# Analyzing threat prevention alert data

If you're up to this stage, you've hopefully collected lots of traffic and threat data. Rather than trying to update every single firewall rule's security profile group at once, we can do it in stages of increasing amounts of analysis required.

1. **Rules with no allowed threats**

The first firewall rules to review are the rules which didn't have any allowed threats. These are the easiest, because since they have no allowed threats, they can have a secure profile attached without any concerns of having any impact whatsoever. Note that we only care about **allowed** threats. Threats which are already blocked are not a concern because **continuing** to block those would not be any change in behavior and so changing the security profile group would not impact any business operations.

The rules without any allowed threat hits can be identified by generating a list of all firewall rules and then removing all rules which had threats. The list of all firewall rules can be exported from the PAN firewall. The list of allowed threats can be obtained by querying your log storage for all allowed threats. In Splunk, the query might look like the following:

```splunk-spl
index=pan_threats action=allowed subtype IN ("spyware", "virus", "vulnerability") severity IN ("medium", "high", "critical")
| stats count by subtype, rule_id, rule, severity, threat_name, threat_id
```

There are a few thoughts behind this query's design:

- `action=allowed` is because we only care about _additional_ blocking which might impact the business, as discussed above.
- We limited to `spyware`, `virus`, and `vulnerability` because those are the major threat prevention components and to scope the analysis. URL Filtering and File Blocking can be handled separately and are discussed later in this post.
- We are limiting the `severity` to `medium`, `high`, and `critical`, consistent with our above goal of mimicking PAN's strict profile which blocks those. We therefore don't care about `low` or `informational` alerts.

Now, comparing the firewall's list of rules against the query output is a task best for machines. So I wrote a [Python script](https://github.com/moshekaplan/palo_alto_firewall_scripts/blob/main/threat_prevention_hardening.py) to do it for me (more on this later).

2. **Rules with a negligible number of allowed threats**

Unfortunately, there marks the end of our freebies. However, firewall rules with "lots" of traffic and "very few" allowed threats should also be able to have a secure Security Profile Group attached with minimal risk to the network's availability and so are relatively easy wins. For arguments sake, let's try to quantify "lots" and "very few" as the following:

- Under 25 threat hits
- More than 250,000 traffic sessions

The reason behind these constraints are that they ensure that we have enough data to analyze, while still having a low enough amount of threats that we can be confident that blocking these will not impact business operations. Even at the minimum constraints, 25 threat hits out of 250,000 would be 0.01% of connections detected as containing threats. For your own environment, you might choose to either tighten or loosen these constraints. Another point to consider is that you might have different criteria for development vs production networks, as failures are generally more tolerable in development networks.

To support this analysis, I created a spreadsheet with the following columns:

- **Device group**
- **Rule type** - `SecurityPreRule` or `SecurityPostRule`
- **Rule Name**
- **Rule UUID**
- **Only Dev** - `True` if all zones involved in at least one side are all development networks
- **Threat hits** - Total count of threats allowed (spyware, virus, and vulnerability)
- **Traffic hits**
- **Percent Threats** - Threat hits as a % of total connections
- **Spyware Hits** - Count of allowed spyware threats
- **Virus hits** - Count of allowed virus threats
- **Vuln Hits** - Count of allowed vulnerability threats
- **Group Profile Setting** - Current assigned Security Profile Group

When a human reviews it, the reviewer will fill in:
- **New Group Profile Setting** - Which Security Profile Group to switch to
- **Notes** - Rationale for decision, any exceptions needed, etc.

I then reviewed this spreadsheet to identify which rules met the criteria of more than 250,000 traffic logs with less than 0.01% threat hits. However, I did not blindly attach the stricter security profile group to these. I still reviewed the threat alerts for each of these, as a rule that allows many ports and applications might have a disproportionally large number of threats for a single allowed protocol which could be problematic. For example, if a rule allows all connections for all protocols between two zones, there might be 100 million connections allowed with only 1,000 threats, which gives us a low percentage of 0.001% of connections detected as containing threats. However, if the 1,000 threats were all related to RDP and there only 25,000 RDP connections, that would mean 4% of RDP connections had a threat detection - which would be potentially hugely impactful.

3. **Rules with a non-negligible number of allowed threats**

The third category of rules were those which had more threat hits than I'd be comfortable blocking without extremely careful analysis.

Some rules had a single threat alert 20,000 times. This would be a clear signal that it's a good candidate for an exception, especially if the threat were for an older vulnerability which is not expected to be present in the environment and so allowing it would not accept additional risk.

Some rules had many threats alerts, but based on the source host, it was clear that they were vulnerability scanners. Likewise other threat alerts had a source user of a known penetration tester. Ideally, we'd filter these out in our initial data collection, either by creating separate firewall rules for our penetration testers and vulnerability scanners, or by filtering them out in our query.

A tricky part is that if you have a jump box, bastion host, a load balancer, or other system effectively doing Network Address Translation (NAT), it'll be impossible to conclusively state whether the traffic is from a vulnerability scanner or not, because you don't have the original IP. In that case, you can try to look for other traffic patterns that might indicative of a vulnerability scanner. Some possibilities include that the threat activities follows the same schedule as your vulnerability scanners or that the types of threats detected are not those that would have false positives occur naturally, like Heartbleed and Log4J.

If you can't conclusively determine that blocking the threats won't be problematic, another possibility is to ask the system owner if they're willing to accept the risk of  potentially blocking legitimate traffic for the sake of better security controls.

If the system owner is unwilling or unreachable, the final option available is to create a new rule above the problematic rule. The new rule would have a lax profile that allows those threats, but is extremely granular to only match the traffic flows generating the threats alerts. The problematic rule below could then have the stricter Security Profile Group attached so that every other traffic flow allowed by the rule will be protected.

# Tightening File Blocking and URL Filtering

Switching to more-secure File Blocking and URL Filtering profiles is more of the same. For File Blocking, all you'd need to do is repeat the steps above: First collect data to determine where those files types are seen, enable blocking where that file type was never seen and so there is no risk, and then examine places the files were seen to ensure that blocking them won't impact the business.

URL Filtering is slightly different in that rather than making exceptions, you'd want to resolve any false positives with PAN prior to implementing blocking. You may also need to create additional rules so that people or systems with a business need to access a blocked category are not prevented from doing so.

# Switching to a secure default

Now that you've determined that blocking threats generally won't cause problems, you might want to consider enabling secure defaults. The way you'd do this is by modifying the `default` Security Profile Group mentioned above. However, don't forget that modifying the `default` Security Profile Group will also change the behavior for all rules currently using it. So instead, first migrate all usage of the `default` Security Profile Group to an `Alert only` Security Profile Group, prior to modifying the `default` Security Profile Group.

# Recap

As a recap, our major steps in deploying PAN Threat Prevention were the following  

1. Decide on your ideal end-state.
    1. Exception groupings (e.g., per system? Per network zone? Inbound vs outbound? Development vs production)
1. Collect data for threat prevention alerts
1. Move rules with no threat hits to the more-secure default rule (easy wins!)
1. Move rules with very low threats, high traffic, and so low %, to more secure rules (less easy wins)
    1. These can often be reviewed quickly
1. Analyze individual rules with large numbers of threats
    1. Look for source system, source user, etc.
    1. Source NAT - Look at time of day to identify scanners
    1. Work with the system owners
    1. Create granular rules if threats need to be allowed
1. Tightening File Blocking and URL Filtering
1. Switching to a secure default

# Implementing threat blocking - Step by Step

Now that we've gone over all of the concepts, here is the step-by-step guide for implementation:

## 1. Decide on your ideal end-state.
    
You need to do this and no one else can do this for you. If in doubt, follow PAN's [recommendations](https://docs.paloaltonetworks.com/best-practices/internet-gateway-best-practices/best-practice-internet-gateway-security-policy/create-best-practice-security-profiles).

## 2. Collect data for threat prevention alerts

The queries below will almost certainly need to be edited for your environment. However, they may still serve as a useful starting point.

Threat data was collected from Splunk with the following query:
```splunk-spl
index=* sourcetype="threat" action=allowed subtype IN ("spyware", "virus", "vulnerability") severity IN ("medium", "high", "critical")
| fillnull value=NULL src_user
| stats count by subtype, rule_uuid, rule, severity, threat_name, threat_id, src_zone, src_ip, src_user, dest_zone, dest_ip, dest_port
```

Traffic data was collected from Splunk with the following query:

```splunk-spl
index=* sourcetype="traffic"
| stats count by rule_uuid, rule
```

URL Filtering data was collected with the following query:

```splunk-spl
index=* sourcetype="threat" subtype="url" action="allowed" http_category IN ("command-and-control", "compromised-website", "dynamic-dns", "encrypted-dns", "grayware", "malware", "phishing", "ransomware", "scanning-activity")
| fillnull value=NULL src_user
| stats count by rule, rule_uuid, http_category, url, src_zone, src_ip, src_user, dest_zone, dest_ip
```

File blocking data was collected with the following query:

```splunk-spl
index=* sourcetype="threat" subtype=file (FileType="Windows Screen Saver SCR File") action=allowed
| fillnull value=NULL src_user
| stats count by rule, rule_uuid, threat_name, src_zone, src_ip, src_user, dest_zone, dest_ip
```

## 3. Move rules with no threat hits to the more-secure default rule (easy wins!)

Update all rules using an insecure Security Profile Group and no threat hits to use the specified Security Profile Group (named `secure` here).

1. Create a file named `insecure_groups.txt` with the list of insecure Security Profile Groups
1. Download your threat logs using a query like the one above
1. Run the [threat_prevention_hardening.py](https://github.com/moshekaplan/palo_alto_firewall_scripts/blob/main/threat_prevention_hardening.py) Python script as follows:
```bash
python threat_prevention_hardening.py --panorama "panorama.example.com" update_no_threat_hits --insecure-groups-fpath insecure_groups.txt --group "secure" --threat-data-fpath "threat_logs.csv"
```

## 4. Move rules with very low threats, high traffic, and so low %, to more secure rules (less easy wins)

As mentioned, these can often be reviewed quickly

We'll first create a spreadsheet with rule hits and statistics for all rules using an insecure Security Profile Group
1. Create a file named `insecure_groups.txt` with the list of insecure Security Profile Groups (or reuse the file from 2a)
2. Download your threat logs using a query like the one above
3. Download your traffic logs using a query like the one above
4. Optional: Create a file with a newline-separate list of your development zones, where you have a higher tolerance for failure
5. Run the [threat_prevention_hardening.py](https://github.com/moshekaplan/palo_alto_firewall_scripts/blob/main/threat_prevention_hardening.py) Python script as follows:
```bash
python threat_prevention_hardening.py --panorama "panorama.example.com" prepare_threat_analysis --dev-zones "dev_zones.txt" --insecure-groups-fpath "insecure_groups.txt" --threat-data-fpath "2025-01-07 - 270d_threat_logs.csv" --threat-data-fpath "2025-01-13 - all allowed threats - onprem.csv" --traffic-data-fpath "2025-01-13 - all rule hits - onprem.csv" --fpath "threat_analysis.csv"
```

## 5. Analyze individual rules with large numbers of threats
As mentioned:
1. Look for source system, source user, etc.
2. Source NAT - Look at time of day to identify scanners
3. Work with the system owners
4. Create granular rules if threats need to be allowed

## 6. Tightening File Blocking and URL Filtering

Update rules using an insecure Security Profile Group and no URL Category hits to use the specified Security Profile Group (`secure` here).

1. Create a file named `insecure_groups.txt` with the list of insecure Security Profile Groups
2. Download your URL Filtering logs using a query like the one above
3. Run the [threat_prevention_hardening.py](https://github.com/moshekaplan/palo_alto_firewall_scripts/blob/main/threat_prevention_hardening.py) Python script as follows:
```bash
python threat_prevention_hardening.py --panorama "panorama.example.com" update_no_threat_hits --insecure-groups-fpath insecure_groups.txt --group "secure" --threat-data-fpath "url_logs.csv"
```

## 7. Switching to a secure default

First replace all usage of the original `default` with a new cloned policy, so that modifying the default Security Profile Group won't change behavior:

1. In Panorama, create a new Security Profile Group by cloning your existing `default` Security Profile Group. For example, we'll call it `Alert only`.
2. Run the [threat_prevention_hardening.py](https://github.com/moshekaplan/palo_alto_firewall_scripts/blob/main/threat_prevention_hardening.py) Python script:
```bash
python threat_prevention_hardening.py --panorama "panorama.example.com" switch_default_usage --group "Alert only"
```

Then modify your `default` rule to contain the same contents as the `secure` profile, so that future rules will have threat prevention enabled by default.

# Final thoughts

Coming up with this process took some time, but allowed us to rigorously improve our usage of threat prevention and set blocking profiles on our firewall rules. Hopefully this writeup is both encouraging and insightful into the process for enabling threat blocking so that you can do the same to improve your network's security.