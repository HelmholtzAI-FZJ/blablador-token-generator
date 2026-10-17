# Backups and restore

## What to back up

| Item | Why |
| --- | --- |
| The PostgreSQL database | Accounts, token hashes and metadata, revocations, deletion records. |
| `app.token_hash_key` | Without it no stored token can be validated, and deletion records no longer match, so deleted accounts could sign in again. Store it separately from the database backups, with the same retention. |
| The configuration | To rebuild the deployment. |

Backups contain password hashes, token hashes and email addresses: encrypt
them and restrict access like the database itself.

## Bundled PostgreSQL: scheduled dumps

Enable the chart's backup job:

```yaml
postgresql:
  backup:
    enabled: true
    schedule: "17 2 * * *"   # daily, 02:17 in the cluster's time zone
    retentionDays: 14
    size: 5Gi
    storageClass: ""          # default storage class
```

Every run writes `tokens-<UTC timestamp>.dump` (PostgreSQL custom format,
readable by its owner only) to the volume
`<release>-blablador-token-generator-postgresql-backup` and deletes its own
dumps older than `retentionDays` (other files, and anything in
subdirectories, are left alone). The job connects as the runtime role over
verified TLS, after waiting up to a minute for the database to accept it. The
volume is kept when the release is uninstalled. Alert on failed backup Jobs
and on the age of the newest dump ([Monitoring](monitoring.md#alerts)).

!!! warning "Copy backups off the cluster"
    A dump on the same storage as the database does not survive losing that
    storage. Copy the backup volume's files to separate storage, for example
    with your cluster backup tool or a job of your own.

Run a backup now and check it:

```bash
kubectl create job --from=cronjob/tokens-blablador-token-generator-postgresql-backup backup-now
kubectl logs job/backup-now    # "Wrote tokens-20261016T213652Z.dump"
```

With a managed PostgreSQL, use the provider's backups and point-in-time
recovery instead, and disable the chart's database.

## Restore

The procedure below restores a dump into the bundled database. Its dump and
restore commands were tested end to end with the hardened images (in Docker,
not on a live cluster); rehearse it on yours.

1. **Stop everything that writes or starts the application.** Suspend GitOps
   auto-sync for the release and any autoscaler, suspend the backup job, scale
   the application to zero and wait until its pods are gone:

    ```bash
    kubectl patch cronjob tokens-blablador-token-generator-postgresql-backup -p '{"spec":{"suspend":true}}'
    kubectl scale deploy/tokens-blablador-token-generator --replicas=0
    kubectl wait --for=delete pod --timeout=120s \
      -l app.kubernetes.io/instance=tokens,app.kubernetes.io/name=blablador-token-generator
    ```

2. **Start a toolbox pod** that mounts the backup volume and the database CA,
   using the PostgreSQL image:

    ```yaml
    apiVersion: v1
    kind: Pod
    metadata:
      name: tokens-restore
      labels:
        # Reuse the backup job's network policy and PostgreSQL access.
        app.kubernetes.io/name: tokens-blablador-token-generator-postgresql-backup
        app.kubernetes.io/instance: tokens
    spec:
      automountServiceAccountToken: false
      securityContext: {runAsNonRoot: true, runAsUser: 70, fsGroup: 70,
                        seccompProfile: {type: RuntimeDefault}}
      containers:
        - name: toolbox
          image: <the PostgreSQL image of the release>
          command: ["sleep", "3600"]
          env:
            - {name: PGHOST, value: tokens-blablador-token-generator-postgresql}
            - {name: PGDATABASE, value: tokens}
            - {name: PGSSLMODE, value: verify-full}
            - {name: PGSSLROOTCERT, value: /tls/ca.crt}
          securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true,
                            capabilities: {drop: ["ALL"]}}
          volumeMounts:
            - {name: backup, mountPath: /backup}
            - {name: ca, mountPath: /tls, readOnly: true}
            - {name: tmp, mountPath: /tmp}
      volumes:
        - name: backup
          persistentVolumeClaim: {claimName: tokens-blablador-token-generator-postgresql-backup}
        - name: ca
          secret: {secretName: tokens-postgresql-tls, items: [{key: ca.crt, path: ca.crt}]}
        - {name: tmp, emptyDir: {}}
    ```

3. **Empty the application schema** as the PostgreSQL administrator, inside
   the database pod (the administrator can sign in only there), and give it
   back to the runtime role:

    ```bash
    kubectl exec -it tokens-blablador-token-generator-postgresql-0 -- psql -U token_admin -d tokens -c \
      "DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION tokens; REVOKE ALL ON SCHEMA public FROM PUBLIC;"
    ```

4. **Restore** as the runtime role (the `password` in the Secret), all or
   nothing:

    ```bash
    kubectl exec -it tokens-restore -- ls -l /backup
    kubectl exec -it tokens-restore -- pg_restore -U tokens --no-owner --role=tokens \
        --single-transaction --exit-on-error -d tokens /backup/tokens-20261016T213652Z.dump
    ```

    **If `pg_restore` fails, do not start the application.** It would
    initialise the empty schema as a new installation, and every deleted
    account could sign in again. Fix the cause and repeat steps 3 and 4.

5. **Start the application**, check that the schema is complete, and resume
   backups:

    ```bash
    kubectl scale deploy/tokens-blablador-token-generator --replicas=2
    kubectl exec deploy/tokens-blablador-token-generator -- python -m app.migrate check
    kubectl patch cronjob tokens-blablador-token-generator-postgresql-backup -p '{"spec":{"suspend":false}}'
    kubectl delete pod tokens-restore
    ```

    `check` compares revision and schema with the release. If the dump came
    from an older release, startup migrates it first.

With Docker Compose the steps are the same: stop the `app` service, run the
`DROP SCHEMA` statement with `docker compose exec postgres psql -U
token_admin -d tokens`, restore with `docker compose exec -T postgres
pg_restore -U tokens --no-owner --role=tokens --single-transaction
--exit-on-error -d tokens < tokens-….dump`, and start `app` again.

!!! danger "Restoring an older backup undoes recent security actions"
    Everything done after the backup was taken is undone, including:

    - revoked tokens work again (`revoke_token`, `revoke_all_credentials`,
      `revoke_user_credentials`), and **rotated tokens accept their old,
      possibly leaked value again** (`rotate_token`);
    - deleted accounts exist again (`delete_user`, `account_deleted`);
    - removed administrator rights and reset passwords are back to their old
      state (`update_user`), and sessions ended by those changes or by logout
      (`logout`, `session_revoked`) become valid again until they expire.

    Before reopening access, rotate `app.secret_key` (this signs everyone
    out), then repeat the actions above from the audit log since the backup's
    timestamp, and check with the identity provider who should still have
    access.

## Testing restores

Restore into a scratch database regularly (at least before go-live and after
major upgrades) and run `python -m app.migrate check` against it. A backup you
have never restored is a hope, not a backup.
