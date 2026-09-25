# HyperDNS cluster: controller and edge nodes

The existing installation stays in `standalone` mode by default. These steps
enable phases 1–3: node enrollment, mutual TLS, and a versioned snapshot of
subscriber access, policies, upstreams, and DoH tokens. There is no shared DNS
address or geographic routing yet.

## 1. Controller

Back up `data.db` and `master.key`, install the new binary, and add these
arguments to the existing daemon's systemd `ExecStart`:

```text
-role controller -controller-url https://CONTROLLER_HOST:9443 -cluster-bind 0.0.0.0:9443
```

`CONTROLLER_HOST` must be reachable from every edge. The cluster listener has
its own CA and server certificate. Edge nodes verify that CA and the fixed
`hyperdns-controller` TLS identity; its URL hostname is only the network
destination. Allow TCP 9443 from edge addresses. The existing dashboard,
resolver, proxy, and subscriber portal continue to run on the controller.

Open the authenticated dashboard's **Nodes** tab. Create a node with its
public IPv4, name and location, and your current admin password. Save the
one-time join token. Download the cluster CA. The token is never shown again;
**Reset join** revokes the old node credential and issues a new token if
enrollment was interrupted or the node key was lost.

## 2. Edge host

### One-line join from the Nodes tab

Create a node in the dashboard, then copy its one-time **Install command** and
run it on a fresh Linux edge host. The command downloads a script over the
dashboard's trusted HTTPS connection. The script uses the one-time join token
to download the same HyperDNS binary that the controller is running, installs
the pinned cluster CA, frees port 53 when `systemd-resolved` owns it, writes the
systemd unit and starts the edge. It opens DNS/proxy ports if UFW or firewalld
is already active; cloud-provider firewall rules still need to be set there.
The token is deleted after successful
enrollment. The dashboard HTTPS origin and controller port 9443 must both be
reachable from the edge. Treat the copied command as a secret until it has run;
use **Reset join** if it is exposed or enrollment fails after consuming it.

For a controller and edge with the same CPU architecture, the running
controller binary is served directly. For a different Linux architecture,
cross-build the edge binary from the **same source revision** and place it on
the controller as `/opt/hyperdns/edge-binaries/hyperdns-linux-amd64` or
`/opt/hyperdns/edge-binaries/hyperdns-linux-arm64` before running the command.
The installer fails clearly if the required binary is missing. For example:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o hyperdns-linux-arm64 ./cmd/hyperdns
# Copy hyperdns-linux-arm64 to the controller's /opt/hyperdns/edge-binaries/
```

The command requires a publicly trusted panel certificate. If the panel is
only available through an SSH tunnel or an internal address that the edge
cannot reach, use the manual steps below.

### Manual join

Copy the same HyperDNS binary to the edge host. Do not run the standalone
installer there: it starts a separate admin panel and modifies local DNS
configuration. Create a private directory and put the downloaded CA and
one-time token in it:

```sh
sudo install -d -m 700 /opt/hyperdns
sudo install -m 644 hyperdns-cluster-ca.pem /opt/hyperdns/cluster-ca.pem
sudo install -m 600 /dev/null /opt/hyperdns/node.join
sudoedit /opt/hyperdns/node.join
```

Paste only the join token into `node.join`. Install the binary at
`/opt/hyperdns/hyperdns`. Copy
[`scripts/hyperdns-edge.service.example`](../scripts/hyperdns-edge.service.example)
to `/etc/systemd/system/hyperdns-edge.service` and replace the node ID,
controller URL and public IP.

Before starting the service, check which process owns DNS port 53:

```sh
sudo ss -lntup | grep ':53'
```

On a fresh Ubuntu/Debian host this is commonly `systemd-resolved`. If the
output shows `systemd-resolved`, disable only its local DNS stub listener:

```sh
sudo install -d -m 755 /etc/systemd/resolved.conf.d
printf '[Resolve]\nDNSStubListener=no\n' | sudo tee /etc/systemd/resolved.conf.d/hyperdns-edge.conf >/dev/null
sudo chmod 644 /etc/systemd/resolved.conf.d/hyperdns-edge.conf
sudo systemctl restart systemd-resolved
```

If `/etc/resolv.conf` points to the disabled stub, switch it to resolved's
upstream list so the host can still resolve the controller hostname:

```sh
readlink -f /etc/resolv.conf
if [ "$(readlink -f /etc/resolv.conf)" = /run/systemd/resolve/stub-resolv.conf ]; then
    sudo ln -sfn /run/systemd/resolve/resolv.conf /etc/resolv.conf
fi
getent hosts example.com
sudo ss -lntup | grep ':53' || true
```

If another process owns port 53, inspect that service before changing it.
Then run:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now hyperdns-edge
sudo journalctl -u hyperdns-edge -f
```

The edge verifies the pinned controller CA, sends a CSR and the one-time token,
and saves its client certificate/key under `/opt/hyperdns/cluster-node`.
It removes `node.join` after successful enrollment. On later starts, the
missing token file is expected; the stored certificate is used. The controller
authenticates that certificate on every snapshot request. Disabled or deleted
nodes cannot fetch snapshots.

An edge starts serving only after it has fetched a valid snapshot, or when a
saved snapshot is less than five minutes old. It polls every 15 seconds. If
the controller remains unreachable for five minutes, DNS and proxy access
close until synchronization resumes. Its encrypted local snapshot is in
`edge-data.db`, protected by its own `edge-master.key`; neither the
controller's `master.key` nor the admin credential is distributed.

Open UDP/TCP 53 and the enabled SNI proxy TCP ports on each edge. DNS answers
for proxied domains point to the edge's own `-public-ip`; direct answers keep
their upstream result. A custom `-config` may set node-local listener,
proxy and TLS settings. DoT/DoH start on an edge only when that config names a
domain and a valid CA-signed certificate/key for it is already installed.

## 3. Check before moving users

1. The Nodes tab must show **Connected** and a snapshot revision.
2. Query an allowed client's test domain against the edge IP over UDP and TCP
   53. A proxied A answer must be the edge's public IP; a direct answer must
   remain the origin result.
3. Disable the node in the panel. Its next snapshot request must be denied.
   Re-enable it and verify the next poll restores service.
4. Change a client IP or policy on the controller and verify the edge reflects
   it after its next poll.

The dashboard also shows a controller-to-edge UDP DNS round-trip time, a TCP
port-53 reachability check, and edge-reported CPU, RAM, DNS QPS, query count,
proxy traffic and active relays. These are refreshed by the controller's
30-second probes and the edge's 15-second authenticated sync. The RTT is a DNS
service probe from the controller; it is not an ICMP ping or a measurement from
the end user's location. A firewall that blocks controller-to-edge DNS probes
can show a failed probe while other clients can still use the edge.

### Current boundaries

- There is no Anycast/global load balancer. Users must select a node IP
  explicitly during this stage.
- Cluster-wide traffic aggregation and quota reservation are not implemented.
  Edges enforce the last controller usage snapshot plus locally observed bytes,
  but those local bytes are not yet reported back. Do not sell a strict shared
  traffic allowance across several edges until the next phase adds reporting.
- Health is a heartbeat from successful snapshot requests, not an active DNS
  and proxy reachability probe. There is no automatic traffic failover yet.
- Node certificates are valid for one year. Before expiry, use **Reset join**
  and enroll the node again with its new token; automatic certificate renewal
  is not part of this stage.
- The controller CA is stored in the controller's encrypted database. Back up
  its `data.db` and `master.key` together. Losing that pair prevents existing
  nodes from joining a replacement controller without a new enrollment.
