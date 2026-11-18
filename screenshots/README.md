# Screenshots

Each image is a screenshot of the query and its results in Splunk, captured from the investigation. Keep the full search bar visible with the results below so the query and its output are both readable.

## Shot list
Capture each in Splunk and save with these filenames so the writeup can reference them:

1. `01-status-codes.png` - the status-code breakdown that ruled out brute force
2. `02-user-agents.png` - the top user agents, with `__main__/0.2` standing out
3. `03-main-session.png` - the full `__main__/0.2` request session
4. `04-loadbalancer-useragents.png` - the mixed user agents that exposed the load balancer
5. `05-elb-realclient.png` - the ELB log revealing the real external client 35.182.246.222
6. `06-s3-breach.png` - the S3 access log showing the GET then the PUT on the bucket
7. `07-byte-counts.png` - the object history, original vs poisoned byte sizes
8. `08-guardduty.png` - the GuardDuty finding that identified the instance
9. `09-osquery-curl.png` - the lone curl, shown to be a benign AWS metadata call
10. `10-detection-fires.png` - the saved detection returning the single external PUT
