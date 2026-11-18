# BOTS v3 investigation: web recon from an external host

Analyst: Evan Alford
Setup: Splunk Enterprise on my own machine, loaded with the Boss of the SOC v3 dataset (`index=botsv3`). The data is from 2018, so I run everything with the time range on All time.
Why: to get real reps at Tier 1 triage and have a documented investigation I can point to.

## Starting point
I started on the web logs (`sourcetype=access_combined`, about 3,900 events) because a web server getting hit is a normal first alert and the logs are easy to read.

My first guess was a brute force or a scan. If that were happening I figured I'd see a couple of noisy IPs and a lot of error codes.

Checked the status codes:
```
index=botsv3 sourcetype=access_combined | stats count by status
```

![Status-code breakdown that ruled out brute force](screenshots/01-status-codes.png)

*Almost all 200s with only a handful of 404s, which is what made me drop the brute-force idea early.*

It came back almost all 200s (3,706), plus 156 304s, 40 404s, and a few others. No wall of 401s or 403s, barely any 404s. So the brute force idea didn't hold up. I reminded myself that a clean status breakdown doesn't really clear anything, since a successful attack still returns 200 and a quiet log can still hide a targeted request. So I kept going.

## Finding the odd client
Instead of chasing error noise I looked at who was hitting the site:
```
index=botsv3 sourcetype=access_combined | top limit=10 useragent
```

![Top user agents, with __main__/0.2 standing out](screenshots/02-user-agents.png)

*Everything reads as a browser or the AWS health checker except __main__/0.2, the Python client that became the lead.*

Most of it was normal: real browser strings, plus ELB-HealthChecker, which is just the AWS load balancer checking the server is up. One line didn't belong: `__main__/0.2` with 197 requests. I didn't recognize it so I looked it up. `__main__` is what Python calls a script you run directly, so this is somebody's Python tool, not a browser. That became my lead.

## Pulling the session
```
index=botsv3 sourcetype=access_combined useragent="__main__/0.2" | table _time, clientip, method, uri_path, uri_query, status | sort _time
```

![The full __main__/0.2 request session](screenshots/03-main-session.png)

*All GETs, all 200s, hitting the same few pages on a loop, which reads as scraping rather than an attack.*

Everything was GET, everything 200, no query strings, and it kept hitting the same few pages (`/`, `/index.php`, `/portal.php`) every few seconds. That ruled out brute force (no POSTs, no logins) and injection (nothing in the query string). It looked automated and focused, more like polling or scraping than a broad scan. All of it showed `clientip` 172.16.0.149, an internal address, which at first made me think the script was running from inside the network.

## Scoping the host
```
index=botsv3 172.16.0.149 | stats count by sourcetype
```
This IP showed up all over the place: web, vpcflow (15,501 events), netstat, osquery, and the stream packet data. Two things stood out. The web logs had 2,818 requests from this IP but only 197 were the script, so it was doing a lot more than the script. And 15k vpcflow records is a lot for one host.

## The correction
Before going further I broke down all the user agents for that IP:
```
index=botsv3 sourcetype=access_combined clientip=172.16.0.149 | stats count by useragent | sort -count
```

![Mixed user agents that exposed the load balancer](screenshots/04-loadbalancer-useragents.png)

*Every kind of client at once on one IP. No single machine looks like that, so 172.16.0.149 is the load balancer, not a suspect.*

The result was basically every kind of client at once: Windows, several different Macs, an iPhone, an Android, Firefox, Googlebot, the ELB health checker, and the script. No single computer looks like that. That is a load balancer carrying everyone's traffic, not a workstation. So 172.16.0.149 is the FrothlyWebLB load balancer, and I'd been about to treat infrastructure as my suspect. In the web logs `clientip` is always the balancer, so the real source was hidden behind it. Glad I checked before escalating anything.

## Who it really was
The load balancer keeps its own access logs that record the actual client, so I went there:
```
index=botsv3 sourcetype=aws:elb:accesslogs "__main__" | table _raw | head 5
```

![ELB log revealing the real external client 35.182.246.222](screenshots/05-elb-realclient.png)

*The load balancer's own logs show the real client behind it: external IP 35.182.246.222 pulling the forum's member pages.*

The raw lines show the real client right after the balancer name. It was 35.182.246.222, an external public IP, hitting the backend web server 172.16.0.178 for www.brewertalk.com. The pages were all forum pages: memberlist.php, search.php, calendar.php, misc.php. The response sizes were 15 to 34 KB, so it was pulling real content, not just checking whether pages existed.

So the source wasn't internal at all. It was an outside host scraping the company forum, and memberlist.php in particular means it was collecting usernames. That is recon, the kind of thing that sets up a later login attack.

## Finding 1
An external host (35.182.246.222) ran an automated Python client (user agent `__main__/0.2`) against Frothly's forum at www.brewertalk.com (backend 172.16.0.178, behind the FrothlyWebLB load balancer). It pulled member list, search, calendar and misc pages, which lines up with reconnaissance and username harvesting. Every request came back 200. I didn't see any brute force or injection in this traffic. Next I want to see everything else this IP did, and watch for login attempts against the usernames it could have grabbed.

## Finding 2 (the real one): open S3 bucket, source code stolen and tampered
Scoping 35.182.246.222 across all logs came back clean of the scary stuff (no CloudTrail, no auth or Windows logs, no firewall), but it showed 7 hits on `aws:s3:accesslogs`. Those turned out to be the actual breach.

The attacker hit the `frothlywebcode` S3 bucket, which was public for both read and write. There was even a file in it called `OPEN_BUCKET_PLEASE_FIX.txt`, so someone already knew it was exposed and had not fixed it.

Sequence, all in about 30 seconds starting 2018-08-20 09:03:44, all scripted (python-requests, then aws-cli, then boto3) from 35.182.246.222:
- HEAD and GET on the bucket to confirm it exists and list what is inside
- GET `OPEN_BUCKET_PLEASE_FIX.txt`
- GET `frothly_html_memcached.tar.gz`, 200, about 3.05 MB downloaded. This is the website source code, so this is data theft out of cloud storage.
- PUT `frothly_html_memcached.tar.gz`, 200, about 3.08 MB. They uploaded a version back that is roughly 19 KB bigger than what they took.

![S3 access log: the external GET then PUT on the bucket](screenshots/06-s3-breach.png)

*The attacker's S3 activity: a GET to steal the source archive, then a PUT to overwrite it with a tampered copy.*

The PUT is the serious part. The bucket was writable, not just readable, so the attacker overwrote the site's code archive with a modified, larger copy. Stealing the code is bad (confidentiality). Rewriting it is worse (integrity), because if that archive gets deployed to the web server, whatever they added, likely a web shell or backdoor, runs on the site. That is how a public bucket turns into a foothold.

My call: confirmed breach, escalate per the IR playbook. Confidentiality, integrity, and possible persistence are all in play.

What I can prove vs what I am still checking: I can prove the code was stolen and the archive was overwritten. Whether the attacker has a live foothold depends on whether the tampered archive was deployed, which is the next thing to confirm. So "they have a way in" is the right worry, but I will confirm it with evidence before stating it as fact.

### Deployment check: it did deploy
I pulled the full access history for the object:
```
index=botsv3 sourcetype=aws:s3:accesslogs frothly_html_memcached.tar.gz | table _time, _raw | sort _time
```

![Object history: original vs poisoned byte sizes](screenshots/07-byte-counts.png)

*The original was 3,057,116 bytes and the attacker's PUT was 3,076,532. That larger size is what a server pulled 29 minutes later.*

Byte counts tie the events together:
- Original object the attacker first downloaded: 3,057,116 bytes.
- Attacker PUT at 09:04:17 (poisoned version): 3,076,532 bytes.
- At 09:33:34, about 29 minutes after the PUT, an EC2 instance using its instance role `assumed-role/EC2InstanceRole/i-0cc93bade2b3cba63` (source 54.183.247.244) did a HEAD then GET and pulled 3,076,532 bytes.

The server pulled the poisoned size, not the original, so the tampered code was downloaded onto an instance. This moves Finding 2 from "possible persistence" to "the tampered artifact was pulled onto a server." Treat the backdoor as deployed until proven otherwise.

Separately, an internal IAM user, bstoll (107.77.212.175), examined the object from 09:59 onward through the S3 console: checked the ACL (403 denied), listed bucket versions, and downloaded it. Reads like an admin or early responder looking at the file, not attacker activity, but noted.

Conclusion: confirmed breach with the tampered artifact deployed to EC2 instance i-0cc93bade2b3cba63. Escalate.

### Chasing the host: it deployed, but I found no backdoor on the box
I identified the instance from a GuardDuty finding. i-0cc93bade2b3cba63 is private IP 172.16.0.145 (public 54.183.247.244), a t2.medium Amazon Linux box in the WebServers autoscaling group. It launched at 09:32:59 and pulled the poisoned archive about 35 seconds later. That timing matters: this is not a one-off deploy. New web servers in that group pull the tampered tar.gz as part of cloud-init, so every machine the group scales up starts out poisoned.

The GuardDuty finding itself was a `Recon:EC2/PortProbeUnprotectedPort`, severity 2. Easy to misread, and I almost did: it is an inbound SSH scan from a China Telecom IP (122.112.243.11), with our instance as the TARGET, not the actor. Background internet noise, and a different IP from the breach. The useful part was that it handed me the instance's real private IP so I could pivot to its logs. It also tells me this box has SSH open to the internet, which is its own problem to fix.

![The GuardDuty finding that identified the instance](screenshots/08-guardduty.png)

*The finding that identified the instance (172.16.0.145) and showed the inbound SSH probe was aimed at it, not launched by it.*

Then I went at the host's process logs (osquery `proc_events`, about 8,200 events) to answer one question: did anything from that archive run? I sorted the executables by how rare they were, since a backdoor runs once, not thousands of times. One stood out, a single `curl`. I pulled its full command and it was curl hitting 169.254.169.254, the AWS metadata service, run by root during boot. Normal cloud-init housekeeping, not a callback. Cleared it. The lesson I keep relearning: rare is a reason to look, not a reason to convict.

![The lone curl, shown to be a benign AWS metadata call](screenshots/09-osquery-curl.png)

*The one rare process on the host was a single curl, and its command showed a benign AWS metadata call. Cleared.*

Checked the two usual persistence spots. Crontab: stock Amazon Linux only (update-motd, raid-check, the hourly run-parts). Listening ports: just 8089, which is Splunk's own management port, expected on a box that forwards logs. No rogue listener, no bind or reverse shell.

Honest call on this host: the tampered code was deployed to it, but I found no standalone backdoor, no persistence, and no attacker process running on the box. That narrows things instead of ending them. A payload that leaves no new binary and no cron job is usually a web shell inside the web content, which runs under the web server and shows up in the web access logs, not the host process logs. That is the next thread: back to the web logs for this server, looking for requests to odd pages after the 09:33 deploy, especially POSTs.

### The web-shell hunt and the gacrux thread: both came back benign
I went looking for a web shell two ways and neither held up.

First, the web logs. I pulled every POST and looked at where they landed:
```
index=botsv3 sourcetype=access_combined method=POST | stats count by uri_path | sort - count
```
Four targets. `/member.php` and `/xmlhttp.php` are normal MyBB forum files (xmlhttp.php handles the forum's AJAX). I checked the 38 POSTs to xmlhttp.php by status and user agent and every one was a real browser returning 200, so that is just members using the site. The other two, `/GponForm/diag_Form` and `/suitecrm/index.php`, are canned exploit-scanner paths (the GPON home-router RCE and a SuiteCRM probe), one hit each, the kind of internet background noise that sprays every public IP. No web shell in the forum.

Second, the deployed host's own network chatter. A web server should barely talk outbound, so I watched its DNS. The only lookups from 172.16.0.145 were `gacrux.i-0cc93bade2b3cba63` and its `.compute.internal` form, 45 each, all NXDomain. For a while I read that as beaconing. It is not. Searching the whole dataset for `gacrux` showed it only in this one host's own telemetry (osquery stamps every row with the hostname), and the cloud-init boot log explained the DNS outright: `httpd` logs `apr_sockaddr_info_get() failed for gacrux ... using 127.0.0.1 for ServerName`. The box is named gacrux (Frothly names hosts after stars), the name is not in DNS, so services keep failing to resolve it and fall back to localhost. The 90 failed lookups were the server tripping over its own hostname, not a callback. The boot log itself is a clean, standard Frothly build (Splunk forwarders to splunk.froth.ly:9998, httpd, memcached, php5), no attacker command in it.

Honest conclusion for the whole execution question: I can prove the theft, the tampering, and the deployment. I cannot, on any evidence I have looked at (process table, cron, listeners, DNS, forum web logs, boot log), show that the planted payload actually ran or called out. That is a legitimate finding, not a gap I am hiding. It changes the IR story from "active live compromise confirmed" to "confirmed exposure and tampering, no confirmed execution yet." The fix is still urgent either way. The one thing I have not been able to inspect directly is the ~19 KB of content the attacker added to the archive, which is what I would want next to say what the payload actually was.

## Indicators
- `__main__/0.2` : non-browser Python user agent, about 200 requests
- 35.182.246.222 : external source of the scraping, main suspect
- 172.16.0.149 : the FrothlyWebLB load balancer, not a suspect
- 172.16.0.178 : the real web server being scraped
- S3 bucket `frothlywebcode` : public read and write, the core misconfiguration
- `frothly_html_memcached.tar.gz` : website source archive, downloaded (stolen) and overwritten with a larger modified copy
- `OPEN_BUCKET_PLEASE_FIX.txt` : note left in the bucket, shows it was known to be open
- EC2 instance `i-0cc93bade2b3cba63` (EC2InstanceRole, source 54.183.247.244) : pulled the poisoned archive, the likely deployment target
- File sizes 3,057,116 (original) vs 3,076,532 (poisoned) : the byte-count link that proves the server pulled the tampered copy
- IAM user `bstoll` (107.77.212.175) : internal user examining the object afterward, looks like admin or responder
- `i-0cc93bade2b3cba63` = 172.16.0.145 (public 54.183.247.244) : confirmed via GuardDuty; WebServers autoscaling group, launched 09:32:59 then pulled the archive 35s later, so the autoscaling group is the deploy path
- 122.112.243.11 : China Telecom scanner, inbound SSH port probe against the instance, unrelated background noise (GuardDuty severity 2, our box was the TARGET)
- Host checks that came back clean : the lone `curl` (AWS metadata 169.254.169.254, benign), crontab (stock Amazon Linux), listening port 8089 (Splunk management, expected)

## ATT&CK, best mapping so far
- T1595 Active Scanning: the automated enumeration of the site
- T1589 Gather Victim Identity Information: pulling usernames from memberlist.php
- T1110 Brute Force: not seen here, but worth watching for next against those usernames
- T1190 Exploit Public-Facing Application: not seen, no injection in these requests
- T1580 / T1619 Cloud Infrastructure and Storage Object Discovery: listing the open bucket
- T1530 Data from Cloud Storage Object: downloading the source archive (theft)
- T1565.001 Stored Data Manipulation: overwriting the archive with a modified version
- T1505.003 Web Shell (looked for, not found): checked the web logs for POSTs to odd pages and the host for rogue processes, cron, and listeners. No web shell turned up. Leaving it mapped as a hypothesis I tested and could not confirm, not a confirmed technique.
- T1195.002 Compromise Software Supply Chain (confirmed as the deploy path): the autoscaling group pulls the modified archive on launch, so the tampered artifact reaches every new web server it spins up
- T1046 Network Service Scanning (third party, inbound): the China Telecom SSH port probe against the instance. Noted as context, not part of the main intrusion.

## Where this landed
Two solid findings and a clear, honest limit. Finding 1: external recon and username harvesting against the forum. Finding 2: a public read/write S3 bucket used to steal the website source and overwrite it with a tampered, larger copy, which the autoscaling group then deployed to its web servers. What I could not prove, after checking every host, network, and web source I had, is that the planted payload actually executed. I am stating that as a finding, not burying it.

## Next
- Characterize the payload itself. The last real unknown is the ~19 KB added to the archive. Worth checking `stream:http` served by 172.16.0.145 to see if any injected script or content shows in what the site handed back, since that is the one angle that could say what the attacker added.
- Add the Splunk Add-on for AWS so the s3, elb and cloudtrail fields parse with real names instead of reading raw lines.
- Turn the strongest detection into a saved Splunk search: an external IP issuing a PUT to the code bucket is the sharpest one. That saved detection is the portfolio centerpiece.
- Package for GitHub and a LinkedIn project. The writeup is honest and complete as it stands: a real breach chain reconstructed from logs, plus a documented, evidence-based decision to stop short of claiming execution.

## The detection I built from this
The sharpest signal in the whole case is the action that started it: an external IP writing to the code bucket. I turned that into a saved Splunk alert. The full search, the MITRE mapping, and the response steps are in `detections/s3-external-put.md`.

![The saved detection firing on the single external PUT](screenshots/10-detection-fires.png)

*The saved detection returning exactly one row: the external IP that wrote to the bucket.*

## Note on method
I left the brute force guess and the load balancer mix-up in these notes on purpose. Both were wrong, and I corrected them with the data. That's the honest version of how the investigation actually went.
