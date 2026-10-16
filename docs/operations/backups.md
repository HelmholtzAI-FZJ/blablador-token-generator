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

Every run writes `tokens-<UTC timestamp>.dump` (PostgreSQL custom format) to
the volume `<release>-blablador-token-generator-postgresql-backup` and deletes
dumps older than `retentionDays`. The job connects as the runtime role over
verified TLS. The volume is kept when the release is uninstalled.

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

1. **Stop the application** so nothing writes during the restore:

    ```bash
    kubectl scale deploy/tokens-blablador-token-generator --replicas=0
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

3. **Empty the application schema** as the PostgreSQL administrator (the
   `admin-password` in the credentials Secret), and give it back to the
   runtime role:

    ```bash
    kubectl exec -it tokens-restore -- psql -U token_admin -c \
      "DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION tokens; REVOKE ALL ON SCHEMA public FROM PUBLIC;"
    ```

4. **Restore** as the runtime role (the `password` in the Secret):

    ```bash
    kubectl exec -it tokens-restore -- ls -l /backup
    kubectl exec -it tokens-restore -- pg_restore -U tokens --no-owner --role=tokens \
        --exit-on-error -d tokens /backup/tokens-20261016T213652Z.dump
    ```

5. **Start the application** and check it:

    ```bash
    kubectl scale deploy/tokens-blablador-token-generator --replicas=2
    kubectl exec deploy/tokens-blablador-token-generator -- python -m app.migrate check
    kubectl delete pod tokens-restore
    ```

    If the dump came from an older release, startup migrates it.

!!! danger "Restoring an older backup undoes recent security actions"
    Tokens revoked and accounts deleted after the backup was taken are valid
    again. Before reopening access, repeat the revocations and deletions made
    since then (audit log events `revoke_token`, `revoke_user_credentials`,
    `delete_user`, `account_deleted`), and check with the identity provider
    who should still have access.

## Testing restores

Restore into a scratch database regularly (at least before go-live and after
major upgrades) and run `python -m app.migrate check` against it. A backup you
have never restored is a hope, not a backup.
