// Idempotent single-node replica set bootstrap for compose.
// Host must be the Compose service name so other containers can discover the primary.
const cfg = {
  _id: "rs0",
  members: [{ _id: 0, host: "mongo:27017" }],
};

function isPrimary() {
  try {
    const h = db.hello();
    return !!(h.isWritablePrimary || h.ismaster);
  } catch (e) {
    return false;
  }
}

try {
  const status = rs.status();
  if (status && status.ok) {
    print("Replica set already initiated: " + status.set);
  } else {
    printjson(rs.initiate(cfg));
  }
} catch (e) {
  print("Initiating replica set rs0...");
  printjson(rs.initiate(cfg));
}

for (let i = 0; i < 60; i++) {
  if (isPrimary()) {
    print("PRIMARY ready on mongo:27017");
    quit(0);
  }
  sleep(1000);
}

print("Timed out waiting for PRIMARY");
quit(1);
