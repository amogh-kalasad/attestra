# Securing the local MongoDB (attestra-mongo-test)

Status on 04 Nov 2026 (checked read-only):

| Item | Current state | Risk |
|---|---|---|
| Server | Docker container `attestra-mongo-test`, image `mongo:7`, command `--replSet rs0` | — |
| Auth | **Off** (no `--auth`, no `--keyFile`) | anyone who can reach the port has full admin |
| Port publish | `0.0.0.0:27017` and `[::]:27017` (Docker Desktop `com.docker.backend`) | reachable from your LAN / Wi-Fi |
| `::1:27017` | `wslrelay.exe` (WSL localhost relay) | loopback only, fine |
| Replica set member | `127.0.0.1:27017` | fine for a single-node local set |
| Data volumes | anonymous volumes: `/data/db` = `5fb0d163113a…`, `/data/configdb` = `1ff9c618e1a6…` | lost if the container is re-created without re-using them |
| Restart policy | `no` | Mongo does not come back after a reboot |

Goal: an admin user, an app user, a test user, auth + keyFile for the replica set,
the port published on `127.0.0.1` only, and the app connecting with a credentialed URI.

> Do this when the app server and worker can be stopped for ~5 minutes. Do **not**
> do it while a scan is running. Passwords are typed at prompts below; they are never
> put on the command line or in shell history. Keep them in your password manager.

Run everything in **PowerShell** on the laptop.

## 0. Look up the exact volume names (copy them for step 3)

```powershell
docker inspect attestra-mongo-test --format "{{range .Mounts}}{{.Destination}} = {{.Name}}{{println}}{{end}}"
```

You get two lines, `/data/db = <DBVOL>` and `/data/configdb = <CFGVOL>`. Use those full names below.

## 1. Create the users (while auth is still off)

```powershell
docker exec -it attestra-mongo-test mongosh --quiet
```

In the mongosh prompt (each `passwordPrompt()` asks for the password; nothing is echoed):

```javascript
const admin = db.getSiblingDB("admin");
// 1) Break-glass admin. Use only for user management.
admin.createUser({ user: "attestra_admin", pwd: passwordPrompt(), roles: [ { role: "root", db: "admin" } ] });
// 2) App user: only the attestra database.
admin.createUser({ user: "attestra_app", pwd: passwordPrompt(),
  roles: [ { role: "readWrite", db: "attestra" }, { role: "dbAdmin", db: "attestra" } ] });
// 3) Test user: the pytest harness creates and drops throwaway attestra_test_<hex> DBs,
//    which needs "any database" roles. Use it ONLY in ATTESTRA_TEST_MONGODB_URI.
admin.createUser({ user: "attestra_test", pwd: passwordPrompt(),
  roles: [ { role: "readWriteAnyDatabase", db: "admin" }, { role: "dbAdminAnyDatabase", db: "admin" } ] });
admin.getUsers().users.map(u => u.user);   // expect the three names
exit
```

`dbAdmin` on `attestra` lets the app create indexes and run its schema migrations.
Use three different, long, random passwords.

## 2. Create the replica-set keyFile (in its own Docker volume)

A replica set with auth must also have internal authentication (a keyFile). The file must be
owned by the container's `mongodb` user (uid 999) and have mode 400.

```powershell
docker volume create attestra-mongo-key
docker run --rm -v attestra-mongo-key:/key mongo:7 bash -c "head -c 756 /dev/urandom | base64 > /key/keyfile && chmod 400 /key/keyfile && chown 999:999 /key/keyfile && ls -l /key"
```

## 3. Re-create the container: auth + keyFile + loopback-only port

The port binding can't be changed on a running container, so you stop the old one, keep it
as a rollback, and start a new one **on the same data volumes**.

```powershell
docker stop attestra-mongo-test
docker rename attestra-mongo-test attestra-mongo-test-old

docker run -d --name attestra-mongo-test --restart unless-stopped `
  -p 127.0.0.1:27017:27017 `
  -v <DBVOL>:/data/db `
  -v <CFGVOL>:/data/configdb `
  -v attestra-mongo-key:/etc/mongo-key:ro `
  mongo:7 --replSet rs0 --bind_ip_all --auth --keyFile /etc/mongo-key/keyfile
```

Notes:
* `-p 127.0.0.1:27017:27017` publishes the port on IPv4 loopback only. The old `0.0.0.0` and `[::]`
  listeners go away. `--bind_ip_all` is only *inside* the container (Docker's port forwarding needs it);
  the host-side restriction is the `127.0.0.1` in `-p`.
* `wslrelay.exe` on `::1:27017` is WSL's localhost relay and is loopback-only. If it still shows after
  the change that is expected; it is not reachable from the network. If it ever shows `0.0.0.0` or `::`
  (all interfaces), restart WSL with `wsl --shutdown`.
* The replica set config (`rs0`, member `127.0.0.1:27017`) lives in the data volume, so it survives.
* Don't add `MONGO_INITDB_ROOT_USERNAME/PASSWORD`: they are ignored for an existing data directory.

## 4. Verify

```powershell
# Only 127.0.0.1 (and possibly the wslrelay ::1) should be listening now.
Get-NetTCPConnection -LocalPort 27017 -State Listen | Select LocalAddress,OwningProcess
docker port attestra-mongo-test        # expect: 27017/tcp -> 127.0.0.1:27017

# Unauthenticated access must be refused:
docker exec attestra-mongo-test mongosh --quiet --eval "db.adminCommand({listDatabases:1})"
#   -> MongoServerError: ... requires authentication

# Authenticated (prompts for the password):
docker exec -it attestra-mongo-test mongosh -u attestra_admin --authenticationDatabase admin --quiet --eval "rs.status().ok"
#   -> 1
```

From another device on your network, `Test-NetConnection <laptop-ip> -Port 27017` must now fail.

## 5. Point Attestra at the credentialed URI

Edit `.env` (do not commit it). URL-encode special characters in passwords
(`@`→`%40`, `:`→`%3A`, `/`→`%2F`, `#`→`%23`, `%`→`%25`), or simply generate passwords
using only letters and digits.

```
ATTESTRA_MONGODB_URI=mongodb://attestra_app:<url-encoded-password>@127.0.0.1:27017/attestra?replicaSet=rs0&authSource=admin
ATTESTRA_MONGODB_DB=attestra
# Tests only (throwaway attestra_test_* databases):
ATTESTRA_TEST_MONGODB_URI=mongodb://attestra_test:<url-encoded-password>@127.0.0.1:27017/?replicaSet=rs0&authSource=admin
```

URI format: `mongodb://<user>:<password>@<host>:<port>/<defaultDb>?replicaSet=rs0&authSource=admin`
* `replicaSet=rs0` is required (transactions).
* `authSource=admin` because the users were created in `admin`.
* Add `&tls=true` (or `ATTESTRA_MONGODB_TLS=true` + `ATTESTRA_MONGODB_TLS_CA_FILE`) for any non-local server.

Then restart the Attestra server and worker (only when the migration work says it's safe).
Check: `attestra mongo-migrate validate` (or the health endpoint) connects without errors.

## 6. Clean up / roll back

* When everything works for a day: `docker rm attestra-mongo-test-old` (the data volumes are shared,
  so **don't** pass `-v` and don't run `docker volume prune`).
* Rollback: `docker stop attestra-mongo-test; docker rm attestra-mongo-test; docker rename attestra-mongo-test-old attestra-mongo-test; docker start attestra-mongo-test`
  and put the old no-auth URI back in `.env`.
* Optional: rename the container to something without "test" (e.g. `attestra-mongo`) the next time it's re-created.

## 7. Kubernetes / Helm

`values.yaml` → `mongodbUri` is now empty by default and **required** when
`persistenceBackend=mongo`: `helm install` fails unless you set `mongodbUri` (stored in the chart Secret) or
provide `existingSecret` containing `ATTESTRA_MONGODB_URI`. In Mongo mode the pods always read
`ATTESTRA_MONGODB_URI` from that Secret. Use the same authenticated URI format as above, with the in-cluster
service host instead of `127.0.0.1`, and enable TLS.
