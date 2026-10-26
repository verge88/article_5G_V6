#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ART="${ROOT}/artifacts/network"
LAB="${ROOT}/.lab/docker_open5gs"
DOCKER_OPEN5GS_COMMIT="${DOCKER_OPEN5GS_COMMIT:-cfac9223bf3a1d10ea5faf31773a7defbd0c6b8f}"
OPEN5GS_TAG="${OPEN5GS_TAG:-v2.8.0}"
UERANSIM_TAG="${UERANSIM_TAG:-v3.3.0}"
NORMAL_REPETITIONS="${NORMAL_REPETITIONS:-6}"
AMF_IP="172.22.0.10"
IMSI="001011234567895"
KI="8baf473f2f8fd09487cccbd7097c6862"
OPC="8E27B6AF0E692E750F32667A3B14605D"

mkdir -p "$ART" "${ROOT}/.lab"
: > "$ART/run.log"
exec > >(tee -a "$ART/run.log") 2>&1

cleanup() {
  set +e
  if [[ -n "${TCPDUMP_PID:-}" ]]; then sudo kill -INT "$TCPDUMP_PID" 2>/dev/null || true; wait "$TCPDUMP_PID" 2>/dev/null || true; fi
  if [[ -d "$LAB" ]]; then
    cd "$LAB"
    for c in mongo nrf scp ausf udr udm pcf bsf nssf amf smf upf webui nr_gnb nr_ue; do docker logs "$c" > "$ART/${c}.log" 2>&1 || true; done
    docker ps -a > "$ART/docker-ps.txt" 2>&1 || true
    docker stats --no-stream --format '{{json .}}' > "$ART/docker-stats.jsonl" 2>&1 || true
    docker compose -f nr-ue.yaml down 2>/dev/null || true
    docker compose -f nr-gnb.yaml down 2>/dev/null || true
    docker compose -f sa-deploy.yaml down -v 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo "== host =="
uname -a
cat /etc/os-release

echo "== prepare host networking =="
sudo sysctl -w net.ipv4.ip_forward=1
sudo modprobe tun || true
ls -l /dev/net/tun || true

echo "== clone pinned docker lab =="
rm -rf "$LAB"
git clone https://github.com/herlesupreeth/docker_open5gs.git "$LAB"
cd "$LAB"
git checkout "$DOCKER_OPEN5GS_COMMIT"
printf 'docker_open5gs_commit=%s\nopen5gs_tag=%s\nueransim_tag=%s\n' "$DOCKER_OPEN5GS_COMMIT" "$OPEN5GS_TAG" "$UERANSIM_TAG" > "$ART/versions.txt"

sed -i -E "s/git checkout [0-9a-f]{40}/git checkout tags\/${OPEN5GS_TAG}/" base/Dockerfile
sed -i -E "s/git checkout tags\/v[0-9.]+/git checkout tags\/${UERANSIM_TAG}/" ueransim/Dockerfile
sed -i "s/opType: 'OP'/opType: 'OPC'/" ueransim/ueransim-ue.yaml
sed -i "s/^UE1_OP=.*/UE1_OP=${OPC}/" .env

echo "== build exact Open5GS/UERANSIM images =="
docker build --pull -t docker_open5gs:kie-${OPEN5GS_TAG} base
docker tag docker_open5gs:kie-${OPEN5GS_TAG} docker_open5gs:latest
docker build --pull -t docker_ueransim:kie-${UERANSIM_TAG} ueransim
docker tag docker_ueransim:kie-${UERANSIM_TAG} docker_ueransim:latest

echo "== start independent AMF-boundary capture before 5GC =="
sudo tcpdump -U -i any -s 0 -w "$ART/sbi.pcap" "tcp port 7777 and host ${AMF_IP}" &
TCPDUMP_PID=$!
sleep 2

echo "== start independent full SBI capture before 5GC =="
sudo dumpcap -i any -f "tcp port 7777" -w "$ART/sbi.pcapng" &
TCPDUMP_PID=$!
sleep 2

echo "== start 5GC =="
docker compose -f sa-deploy.yaml up -d mongo nrf scp ausf udr udm pcf bsf nssf amf smf upf webui

wait_log() {
  local container="$1" pattern="$2" timeout="${3:-90}" start now
  start=$(date +%s)
  while true; do
    if docker logs "$container" 2>&1 | grep -Eqi "$pattern"; then return 0; fi
    now=$(date +%s); if (( now-start > timeout )); then echo "timeout waiting for $container: $pattern"; docker logs "$container" | tail -200; return 1; fi
    sleep 2
  done
}

sleep 12
docker ps --format 'table {{.Names}}\t{{.Status}}' | tee "$ART/core-status.txt"
docker exec webui /open5gs/misc/db/open5gs-dbctl add_ue_with_apn "$IMSI" "$KI" "$OPC" internet || \
  docker exec webui misc/db/open5gs-dbctl add_ue_with_apn "$IMSI" "$KI" "$OPC" internet

echo "== start UERANSIM gNB =="
docker compose -f nr-gnb.yaml up -d
wait_log nr_gnb 'NG Setup procedure is successful|NG Setup.*success' 90

success_count() { docker logs nr_ue 2>&1 | grep -Eic 'PDU Session establishment is successful|PDU Session.*success' || true; }
wait_new_success() {
  local before="$1" timeout="${2:-75}" start now cur
  start=$(date +%s)
  while true; do
    cur=$(success_count)
    if (( cur > before )); then return 0; fi
    now=$(date +%s); if (( now-start > timeout )); then echo "timeout waiting for a new UE PDU session success"; docker logs nr_ue | tail -200; return 1; fi
    sleep 2
  done
}

echo "== network-derived normal episodes =="
for i in $(seq 1 "$NORMAL_REPETITIONS"); do
  before=$(success_count)
  if docker inspect nr_ue >/dev/null 2>&1; then docker restart nr_ue >/dev/null; else docker compose -f nr-ue.yaml up -d; fi
  wait_new_success "$before" 75
  echo "normal episode $i complete"
  if (( i == (NORMAL_REPETITIONS+1)/2 )); then
    echo "restarting SCP to force a new observed AMF-SCP HTTP/2 connection epoch"
    docker restart scp >/dev/null
    sleep 10
  fi
done

echo "== unsupported-DNN episode =="
cp ueransim/ueransim-ue.yaml "$ART/ueransim-ue.normal.yaml"
sed -i "s/apn: 'internet'/apn: 'kie-invalid'/" ueransim/ueransim-ue.yaml
before=$(success_count)
docker restart nr_ue >/dev/null || true
sleep 18
cp "$ART/ueransim-ue.normal.yaml" ueransim/ueransim-ue.yaml

echo "== restore normal UE once =="
before=$(success_count)
docker restart nr_ue >/dev/null
wait_new_success "$before" 75

sudo kill -INT "$TCPDUMP_PID" || true
wait "$TCPDUMP_PID" || true
unset TCPDUMP_PID
sync
ls -lh "$ART/sbi.pcapng"
stat -c '%s' "$ART/sbi.pcapng" > "$ART/pcap-bytes.txt"

echo "== decode Nsmf_PDUSession CreateSMContext from PCAP =="
python3 "$ROOT/experiment/extract_sbi.py" --pcap "$ART/sbi.pcapng" --output "$ART/events.json" --client-ip "$AMF_IP"
cat "$ART/events.json"
python3 - "$ART/events.json" <<'PY'
import json, re, sys
payload=json.load(open(sys.argv[1])); events=payload['events']; capture_meta=payload.get('capture_metadata',{})
create=re.compile(r'^/nsmf-pdusession/v[0-9]+/sm-contexts(?:\?.*)?$')
if len(events) < 3:
    raise SystemExit(f'too few CreateSMContext attempts decoded: {len(events)}')
bad=[e['path'] for e in events if not create.fullmatch(e['path'])]
if bad:
    raise SystemExit(f'non-CreateSMContext paths leaked into profile: {bad[:5]}')
if not any(e.get('http_status') == 201 for e in events):
    raise SystemExit('no HTTP 201 CreateSMContext response decoded; witness capture/parser is incomplete')
epochs={e['connection_epoch'] for e in events}
if len(epochs) < 2:
    raise SystemExit(f'connection-epoch scenario not exercised: only {epochs}')
if not capture_meta.get('same_stream_id_across_connections'):
    raise SystemExit('HTTP/2 stream-ID reuse across connections was not observed')
print(f'validated {len(events)} CreateSMContext attempts across {len(epochs)} HTTP/2 connection epochs')
PY

docker exec nr_ue sh -lc 'ip addr; ping -c 2 -W 2 -I uesimtun0 8.8.8.8' > "$ART/user-plane-smoke.txt" 2>&1 || true

echo "network phase complete"
