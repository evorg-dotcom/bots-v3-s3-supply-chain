# Detection: External IP Writing to an S3 Bucket

## What it catches
An S3 object write (PUT) coming from a public IP address. Legitimate writes to a code or content bucket come from inside AWS or from internal infrastructure. A write from an external address is either a misconfiguration being abused or an attacker tampering with stored objects.

In the BOTS v3 case this repo documents, this rule fires on the exact action that gave the attacker a foothold: an external host (35.182.246.222) overwrote the website source archive in a public read/write bucket, which the autoscaling group then deployed.

## Search
See `s3-external-put.spl`.

## Logic, line by line
- Pulls only S3 write operations (`REST.PUT.OBJECT`). PUT is the dangerous verb, it overwrites an object.
- Three `rex` extractions carve the bucket name, the remote IP, and the object key out of the raw log, so no AWS add-on is required.
- The `cidrmatch` block drops the three private ranges (10/8, 172.16/12, 192.168/16) so only external sources survive.
- `table` leaves a clean "who wrote what, from where."

## MITRE ATT&CK
- T1565.001 Stored Data Manipulation
- T1195.002 Compromise Software Supply Chain

## Save as an alert
- Schedule: rolling 15 minutes in production. Any cadence works in a static lab.
- Trigger condition: number of results is greater than 0.
- Severity: high.

Saved-search stanza (savedsearches.conf):

```
[S3 - External IP Writing to Bucket]
search = index=botsv3 sourcetype=aws:s3:accesslogs "REST.PUT.OBJECT" | rex field=_raw "^\S+\s+(?<bucket>\S+)\s+\[" | rex field=_raw "\]\s+(?<remote_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s" | rex field=_raw "REST\.PUT\.OBJECT\s+(?<s3_key>\S+)" | where NOT cidrmatch("10.0.0.0/8", remote_ip) AND NOT cidrmatch("172.16.0.0/12", remote_ip) AND NOT cidrmatch("192.168.0.0/16", remote_ip) | table _time, remote_ip, bucket, s3_key
dispatch.earliest_time = 0
dispatch.latest_time = now
cron_schedule = */15 * * * *
alert.severity = 5
counttype = number of events
relation = greater than
quantity = 0
```

## Response steps
1. Identify the object and bucket that were written.
2. Pull the object from any deploy or build path immediately, before the next scale-up or deployment serves it.
3. Compare the object against a known-good version by hash or byte size.
4. Lock the bucket policy to block public and external writes.
5. Rotate any credentials or instance roles that pulled the object.

## Notes and limits
- With the Splunk Add-on for AWS the field extractions become automatic and this search gets shorter.
- The rule flags external writes to any bucket, not just the one in this case, on purpose. It should generalize to other environments.
- Tune by allowlisting known external automation IPs if any legitimately write to buckets.
