#!/usr/bin/env python3
import argparse, json, re, subprocess, sys, xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path

CREATE_SM_CONTEXT_RE = re.compile(r"^/nsmf-pdusession/v[0-9]+/sm-contexts(?:\\?.*)?$")

def field_values(elem, name):
    vals=[]
    for f in elem.iter('field'):
        if f.attrib.get('name') == name:
            v=f.attrib.get('show') or f.attrib.get('value') or f.attrib.get('showname')
            if v is not None:
                vals.append(v)
    return vals

def header_pairs(stream_elem):
    pairs=[]
    for h in stream_elem.iter('field'):
        if h.attrib.get('name') == 'http2.header':
            names=field_values(h,'http2.header.name')
            vals=field_values(h,'http2.header.value')
            for n,v in zip(names,vals):
                pairs.append((n,v))
    if not pairs:
        names=field_values(stream_elem,'http2.header.name')
        vals=field_values(stream_elem,'http2.header.value')
        pairs=list(zip(names,vals))
    return pairs

def parse_pdml(pdml_path, smf_ip=None, client_ip=None):
    root=ET.parse(pdml_path).getroot()
    streams=defaultdict(lambda:{'times':[],'requests':[],'statuses':[],'srcs':[],'dsts':[]})
    for pkt in root.findall('packet'):
        frame=next((p for p in pkt.findall('proto') if p.attrib.get('name')=='frame'),None)
        tcp=next((p for p in pkt.findall('proto') if p.attrib.get('name')=='tcp'),None)
        ip=next((p for p in pkt.findall('proto') if p.attrib.get('name') in ('ip','ipv6')),None)
        h2=next((p for p in pkt.findall('proto') if p.attrib.get('name')=='http2'),None)
        if tcp is None or h2 is None:
            continue
        tcp_streams=field_values(tcp,'tcp.stream')
        if not tcp_streams:
            continue
        tcp_stream=tcp_streams[0]
        t=(field_values(frame,'frame.time_epoch')[0] if frame is not None and field_values(frame,'frame.time_epoch') else None)
        src=(field_values(ip,'ip.src') or field_values(ip,'ipv6.src') or [None])[0] if ip is not None else None
        dst=(field_values(ip,'ip.dst') or field_values(ip,'ipv6.dst') or [None])[0] if ip is not None else None
        stream_fields=[f for f in h2.iter('field') if f.attrib.get('name')=='http2.stream']
        if not stream_fields:
            stream_fields=[h2]
        for se in stream_fields:
            ids=[v for v in field_values(se,'http2.streamid') if str(v).isdigit()]
            if not ids:
                ids=[v for v in field_values(se,'http2.stream') if str(v).isdigit()]
            if not ids:
                continue
            sid=ids[0]
            headers=dict(header_pairs(se))
            key=(tcp_stream,sid)
            rec=streams[key]
            if t: rec['times'].append(float(t))
            if src: rec['srcs'].append(src)
            if dst: rec['dsts'].append(dst)
            method=(field_values(se,'http2.headers.method') or [headers.get(':method')])[0]
            path=(field_values(se,'http2.headers.path') or [headers.get(':path')])[0]
            status=(field_values(se,'http2.headers.status') or [headers.get(':status')])[0]
            if method and path:
                rec['requests'].append({'method':method,'path':path,'time':float(t) if t else None,'src':src,'dst':dst})
            if status:
                rec['statuses'].append({'status':status,'time':float(t) if t else None,'src':src,'dst':dst})
    events=[]
    for (tcp_stream,sid),rec in sorted(streams.items(), key=lambda kv:(int(kv[0][0]),int(kv[0][1]))):
        reqs=[r for r in rec['requests'] if r['method'].upper()=='POST' and r['path'].split('?',1)[0]=='/nsmf-pdusession/v1/sm-contexts']
        if not reqs:
            continue
        req=reqs[0]
        if client_ip and req.get('src') and req['src'] != client_ip:
            continue
        if smf_ip and req.get('dst') and req['dst'] != smf_ip:
            continue
        statuses=sorted(rec['statuses'], key=lambda x:x['time'] or 0)
        st=statuses[0]['status'] if statuses else None
        if st == '201': outcome='S'
        elif st and st.isdigit() and 300 <= int(st) < 400: outcome='D'
        elif st: outcome='E'
        else: outcome='P'
        end=statuses[0]['time'] if statuses else None
        latency_ms=(end-req['time'])*1000 if end is not None and req['time'] is not None else None
        events.append({
            'attempt_id':f'{tcp_stream}:{sid}',
            'connection_epoch':int(tcp_stream),
            'stream_id':int(sid),
            'request_time':req['time'],
            'response_time':end,
            'latency_ms':latency_ms,
            'http_status':int(st) if st and st.isdigit() else None,
            'truth':outcome,
            'path':req['path'],
            'source':'pcap',
        })
    sid_to_connections=defaultdict(set)
    for tcp_stream,sid in streams:
        sid_to_connections[int(sid)].add(int(tcp_stream))
    capture_metadata={
        'all_http2_connection_epochs':len({int(tcp_stream) for tcp_stream,_ in streams}),
        'same_stream_id_across_connections':any(len(connections)>1 for connections in sid_to_connections.values()),
        'reused_stream_ids':sorted([sid for sid,connections in sid_to_connections.items() if len(connections)>1]),
    }
    return events,capture_metadata

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--pcap', required=True)
    ap.add_argument('--output', required=True)
    ap.add_argument('--smf-ip', default=None)
    ap.add_argument('--client-ip', default=None)
    ap.add_argument('--pdml', default=None)
    args=ap.parse_args()
    pdml=Path(args.pdml or (str(Path(args.output).with_suffix('.pdml'))))
    cmd=['tshark','-r',args.pcap,'-d','tcp.port==7777,http2','-Y','tcp.port == 7777 && http2','-T','pdml']
    with pdml.open('wb') as f:
        p=subprocess.run(cmd,stdout=f,stderr=subprocess.PIPE)
    if p.returncode != 0:
        sys.stderr.write(p.stderr.decode(errors='replace'))
        raise SystemExit(p.returncode)
    events,capture_metadata=parse_pdml(pdml,args.smf_ip,args.client_ip)
    Path(args.output).write_text(json.dumps({'profile':'Nsmf_PDUSession CreateSMContext','events':events,'capture_metadata':capture_metadata},indent=2),encoding='utf-8')
    print(f'extracted {len(events)} CreateSMContext attempts')
    if not events:
        raise SystemExit('no CreateSMContext attempts decoded from PCAP')
    success=sum(e['truth']=='S' for e in events)
    epochs=len(set(e['connection_epoch'] for e in events))
    if success == 0:
        raise SystemExit('CreateSMContext requests were seen, but no 201 response was decoded; capture must start before HTTP/2 connection establishment')
    if epochs < 2:
        raise SystemExit(f'expected at least two observed HTTP/2 connection epochs, got {epochs}')

if __name__=='__main__': main()
