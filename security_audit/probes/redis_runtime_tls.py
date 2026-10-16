import json, os, pathlib, subprocess, tempfile, time, uuid
from urllib.parse import quote
import redis
from limits.storage import storage_from_string
from limits.strategies import FixedWindowRateLimiter
from limits import parse
project=pathlib.Path(__file__).resolve().parents[2]
container='token-generator-redis-tls-'+uuid.uuid4().hex[:12]
report=project/'security_audit/evidence/repeated-redis-runtime-test.json'
result={'container':container,'synthetic_only':True}
with tempfile.TemporaryDirectory(prefix='token-generator-redis-synthetic-tls-') as directory:
 p=pathlib.Path(directory)
 def run(command,**kwargs):return subprocess.run(command,capture_output=True,text=True,check=True,**kwargs)
 run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(p/'ca.key'),'-out',str(p/'ca.crt'),'-days','1','-subj','/CN=TokenGeneratorSyntheticRedisCA'])
 run(['openssl','req','-newkey','rsa:2048','-nodes','-keyout',str(p/'server.key'),'-out',str(p/'server.csr'),'-subj','/CN=localhost'])
 (p/'extensions.cnf').write_text('subjectAltName=DNS:localhost,DNS:redis,IP:127.0.0.1\n')
 run(['openssl','x509','-req','-in',str(p/'server.csr'),'-CA',str(p/'ca.crt'),'-CAkey',str(p/'ca.key'),'-CAcreateserial','-out',str(p/'server.crt'),'-days','1','-extfile',str(p/'extensions.cnf')])
 (p/'server.key').chmod(0o644)
 password="SyntheticRedisP@ss'word:/+?&1234567890"
 cmd=['docker','run','--rm','--detach','--name',container,'--user','999:999','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','64','--memory','128m','--cpus','0.5','--tmpfs','/data:rw,noexec,nosuid,size=16m,uid=999,gid=999','--tmpfs','/tls:rw,noexec,nosuid,size=16m,uid=999,gid=999,mode=0700','-v',str(p)+':/cert-src:ro','-v',str(project/'helm/blablador-token-generator/files/redis-entrypoint.sh')+':/startup/redis-entrypoint.sh:ro','-p','127.0.0.1::6379','-e','REDIS_PASSWORD='+password,'--entrypoint','sh','token-generator-redis:security-fixed','-ec','cp /cert-src/server.crt /tls/tls.crt; cp /cert-src/server.key /tls/tls.key; cp /cert-src/ca.crt /tls/ca.crt; chmod 600 /tls/tls.key; exec /startup/redis-entrypoint.sh --save "" --appendonly no --maxmemory 64mb --maxmemory-policy noeviction --port 0 --tls-port 6379 --tls-cert-file /tls/tls.crt --tls-key-file /tls/tls.key --tls-ca-cert-file /tls/ca.crt --tls-auth-clients no']
 try:
  run(cmd)
  print('Isolated TLS-only least-privilege Redis created',flush=True)
  port=run(['docker','port',container,'6379/tcp']).stdout.strip().split(':')[-1]
  result['image_id']=run(['docker','inspect','--format','{{.Image}}',container]).stdout.strip()
  uri=f'rediss://:{quote(password,safe="")}@127.0.0.1:{port}/0?ssl_ca_certs={quote(str(p/"ca.crt"),safe="")}&ssl_cert_reqs=required&ssl_check_hostname=true'
  client=redis.Redis.from_url(uri,socket_timeout=1,socket_connect_timeout=1)
  deadline=time.monotonic()+60
  while time.monotonic()<deadline:
   try:
    if client.ping():break
   except redis.RedisError:pass
   time.sleep(1)
  else:
   result['logs']=run(['docker','logs',container]).stdout
   raise RuntimeError('Redis TLS startup failed')
  result['tls_verified_authenticated']=client.ping()
  storage=storage_from_string(uri,socket_timeout=1,socket_connect_timeout=1)
  limiter=FixedWindowRateLimiter(storage)
  result['shared_rate_limit']=[limiter.hit(parse('2/minute'),'synthetic-security-audit') for _ in range(3)]
  assert result['shared_rate_limit']==[True,True,False],result
  result['dangerous_commands_denied']={}
  for command in ['CONFIG GET maxmemory-policy','FLUSHALL','ACL LIST']:
   try:client.execute_command(*command.split())
   except redis.exceptions.NoPermissionError:result['dangerous_commands_denied'][command]=True
   else:result['dangerous_commands_denied'][command]=False
  assert all(result['dangerous_commands_denied'].values()),result
  plain=redis.Redis(host='127.0.0.1',port=int(port),password=password,socket_timeout=1,socket_connect_timeout=1)
  try:plain.ping()
  except redis.RedisError:result['plaintext_rejected']=True
  else:result['plaintext_rejected']=False
  wrong=redis.Redis.from_url(uri.replace(quote(password,safe=''),'IncorrectSyntheticPassword'),socket_timeout=1,socket_connect_timeout=1)
  try:wrong.ping()
  except redis.exceptions.AuthenticationError:result['incorrect_password_rejected']=True
  else:result['incorrect_password_rejected']=False
  system_ca=redis.Redis(host='127.0.0.1',port=int(port),password=password,ssl=True,ssl_cert_reqs='required',ssl_check_hostname=True,socket_timeout=1,socket_connect_timeout=1)
  try:system_ca.ping()
  except redis.RedisError:result['untrusted_ca_rejected']=True
  else:result['untrusted_ca_rejected']=False
  assert result['plaintext_rejected'] and result['incorrect_password_rejected'] and result['untrusted_ca_rejected'],result
  result['passed']=True
 finally:
  result['cleanup_exit']=subprocess.run(['docker','rm','--force',container],capture_output=True).returncode
  report.write_text(json.dumps(result,indent=2))
 print(json.dumps({k:v for k,v in result.items() if k!='logs'},indent=2),flush=True)
