# BOTS v3: S3 Supply-Chain Tampering Investigation

A full Tier 1 to Tier 2 SOC investigation I ran against the Splunk Boss of the SOC v3 dataset, documented end to end, plus a working detection built from what I found.

## What this shows
- Triaging a routine web alert down to a confirmed breach using raw logs.
- Correcting my own wrong assumptions with data. I left the mistakes in the writeup on purpose, because that is how the investigation actually went.
- Reconstructing a supply-chain attack: external recon, a public read/write S3 bucket, source-code theft, tampering, and automated deployment to a web fleet.
- Knowing where the evidence stops. I proved the theft, the tampering, and the deployment. I could not prove the planted payload executed, and I say so rather than claiming a cleaner story than the data supports.
- Turning the investigation into a saved Splunk detection that catches the root action.

## The short version
An external host scraped the company forum for usernames, then found an S3 bucket left public for both read and write. It downloaded the website's source archive (theft), then uploaded a tampered copy about 19 KB larger (integrity). The autoscaling group pulled that poisoned archive onto new web servers automatically at boot. I tracked the whole chain through S3 access logs, ELB logs, GuardDuty, osquery, and Splunk Stream.

## Contents
- `case-writeup.md` - the investigation, in order, with the SPL I ran at each step.
- `detections/` - the saved detection: the SPL, its documentation, and response steps.
- `screenshots/` - Splunk output from each stage.

## Detection
The sharpest signal is the action that started it all: an external IP writing to the bucket. See `detections/s3-external-put.md`.

## Dataset
Splunk Boss of the SOC v3 (publicly available). The data is from 2018, so every search runs with the time range set to All time.
