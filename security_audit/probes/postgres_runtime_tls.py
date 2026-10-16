import json, os, pathlib, subprocess, tempfile, time, uuid
project=pathlib.Path(__file__).resolve().parents[2]
container='token-generator-role-tls-'+uuid.uuid4().hex[:12]
report=pathlib.Path('/private/tmp/token-generator-runtime-role-test-fixed-result.json')
result={'container':container,'synthetic_only':True}
with tempfile.TemporaryDirectory(prefix='token-generator-synthetic-tls-') as directory:
 p=pathlib.Path(directory)
 def run(command,**kwargs):
  return subprocess.run(command,capture_output=True,text=True,check=True,**kwargs)
 run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(p/'ca.key'),'-out',str(p/'ca.crt'),'-days','1','-subj','/CN=TokenGeneratorSyntheticAuditCA'])
 run(['openssl','req','-newkey','rsa:2048','-nodes','-keyout',str(p/'server.key'),'-out',str(p/'server.csr'),'-subj','/CN=localhost'])
 (p/'extensions.cnf').write_text('subjectAltName=DNS:localhost,DNS:postgres,IP:127.0.0.1\n')
 run(['openssl','x509','-req','-in',str(p/'server.csr'),'-CA',str(p/'ca.crt'),'-CAkey',str(p/'ca.key'),'-CAcreateserial','-out',str(p/'server.crt'),'-days','1','-extfile',str(p/'extensions.cnf')])
 (p/'server.key').chmod(0o644)
 password="SyntheticAuditP@ss'word:/+?&1234567890"
 cmd=['docker','run','--rm','--detach','--name',container,'--user','70:70','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','128','--memory','768m','--cpus','1','--tmpfs','/var/lib/postgresql/data:rw,noexec,nosuid,size=512m,uid=70,gid=70,mode=0700','--tmpfs','/var/run/postgresql:rw,nosuid,size=16m,uid=70,gid=70','--tmpfs','/tmp:rw,noexec,nosuid,size=16m,uid=70,gid=70','--tmpfs','/tls:rw,noexec,nosuid,size=16m,uid=70,gid=70,mode=0700','-v',str(p)+':/cert-src:ro','-v',str(project/'helm/blablador-token-generator/files/init-runtime-role.sh')+':/docker-entrypoint-initdb.d/10-runtime-role.sh:ro','-p','127.0.0.1::5432','-e','POSTGRES_USER=token_admin','-e','POSTGRES_DB=tokens','-e','POSTGRES_PASSWORD=SyntheticSeparateAdminPassword1234567890','-e','TOKEN_DB_USER=tokens','-e','TOKEN_DB_PASSWORD='+password,'-e','TOKEN_DB_REQUIRE_TLS=true','--entrypoint','sh','token-generator-postgresql:security-fixed','-ec','cp /cert-src/server.crt /tls/tls.crt; cp /cert-src/server.key /tls/tls.key; cp /cert-src/ca.crt /tls/ca.crt; chmod 600 /tls/tls.key; exec /usr/local/bin/docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tls/tls.crt -c ssl_key_file=/tls/tls.key -c ssl_ca_file=/tls/ca.crt']
 try:
  run(cmd)
  result['image_id']=run(['docker','inspect','--format','{{.Image}}',container]).stdout.strip()
  print('Isolated TLS-only runtime-role container created',flush=True)
  connection=['docker','exec','-e','PGPASSWORD='+password,'-e','PGSSLMODE=verify-full','-e','PGSSLROOTCERT=/tls/ca.crt',container,'psql','-h','127.0.0.1','-U','tokens','-d','tokens','-Atc']
  deadline=time.monotonic()+60
  while time.monotonic()<deadline:
   probe=subprocess.run(connection+['SELECT 1;'],capture_output=True,text=True)
   if probe.returncode==0: break
   time.sleep(1)
  else:
   result['logs']=run(['docker','logs',container]).stdout
   raise RuntimeError('Runtime-role TLS startup failed')
  result['privileges']=run(connection+["SELECT rolsuper::text || ':' || rolcreatedb::text || ':' || rolcreaterole::text FROM pg_roles WHERE rolname=current_user;"]).stdout.strip()
  result['schema_owned']=run(connection+["SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='public';"]).stdout.strip()
  result['ddl_dml']=run(connection+['CREATE TABLE audit_canary(id int PRIMARY KEY); INSERT INTO audit_canary VALUES(1); SELECT id FROM audit_canary; DROP TABLE audit_canary;']).stdout.strip()
  plain=['docker','exec','-e','PGPASSWORD='+password,'-e','PGSSLMODE=disable',container,'psql','-h','127.0.0.1','-U','tokens','-d','tokens','-Atc','SELECT 1;']
  rejection=subprocess.run(plain,capture_output=True,text=True)
  result['plaintext_rejected']=rejection.returncode!=0
  result['plaintext_error']=rejection.stderr.strip()
  escalation=subprocess.run(connection+['CREATE ROLE forbidden_role SUPERUSER;'],capture_output=True,text=True)
  result['privilege_escalation_rejected']=escalation.returncode!=0
  assert result['privileges']=='false:false:false',result
  assert result['schema_owned']=='tokens',result
  assert result['plaintext_rejected'] and result['privilege_escalation_rejected'],result
  result['passed']=True
 finally:
  result['cleanup_exit']=subprocess.run(['docker','rm','--force',container],capture_output=True).returncode
  report.write_text(json.dumps(result,indent=2))
 print(json.dumps({k:v for k,v in result.items() if k!='logs'},indent=2),flush=True)
