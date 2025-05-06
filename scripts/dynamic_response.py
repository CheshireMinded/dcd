#!/usr/bin/env python3
"""
dynamic_response.py

This module defines DynamicResponseManager, orchestrating:
- Cognitive-bias based honeypot scaling
- Deceptive responses and decoy generation
- Persistent attacker profiling
- Elasticsearch logging with retry queue
- File-based JSON event emission for Filebeat/Kafka
- MITRE ATT&CK TTP enrichment
- FastAPI HTTP endpoint for event-driven processing
- Prometheus metrics exposure and ELK queue length tracking
"""

import os
import json
import time
import random
from datetime import datetime
from typing import Dict, Any, List, Tuple
from dataclasses import dataclass
import logging
import logging.handlers
import docker
import requests
from docker.errors import NotFound, APIError
from prometheus_client import Counter, Histogram, Gauge, start_http_server
from fastapi import FastAPI, Request

# Optional JSON logging formatter
try:
    from pythonjsonlogger import jsonlogger
except ImportError:
    jsonlogger = None
# Optional MITRE ATT&CK enrichment
try:
    from mitreattack.stix20 import MitreAttackData
except ImportError:
    MitreAttackData = None
# Optional environment loader
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Configuration via ENV
ES_HOST        = os.getenv('ES_HOST', 'localhost')
ES_PORT        = int(os.getenv('ES_PORT', '9200'))
STATE_FILE     = os.getenv('STATE_FILE', '/home/student/dcd-unified/state/attacker_state.json')
ELK_QUEUE_FILE = os.getenv('ELK_QUEUE_FILE', '/home/student/dcd-unified/state/elk_retry_queue.jsonl')
LOG_FILE       = os.getenv('DR_LOG_FILE', '/var/log/dcd/dynamic_response.log')
TTP_DATA_FILE  = os.getenv('TTP_DATA_FILE', '/home/student/dcd-unified/data/enterprise-attack.json')

# Map our deception "response types" to ATT&CK technique IDs
RESPONSE_TTP_MAP: Dict[str, str] = {
    'misleading_info': 'T1584',    # Masquerading
    'fake_error':      'T1499',    # Resource Hijacking
    'decoy_file':      'T1027',    # Obfuscated Files or Information
    'delayed_response':'',         # no direct mapping
    'fake_success':    'T1105',    # Ingress Tool Transfer
    'challenge':       ''          # no direct mapping
}

HONEYPOTS = [
    {'name':'cowrie',     'service':'cowrie_cowrie',                              'bias':'anchoring'},
    {'name':'dionaea',    'service':'dionaea_dionaea',                            'bias':'confirmation'},
    {'name':'elasticpot', 'service':'elasticpot_honeypot_elasticpot_triggered',   'bias':'overconfidence'},
    {'name':'heralding',  'service':'heralding_honeypot_heralding_triggered',     'bias':'overconfidence'},
    {'name':'tanner',     'service':'tanner_honeypot_tanner_triggered',           'bias':'anchoring'}
]

# Ensure log directory exists
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# Logger setup for file JSON logs
logger = logging.getLogger('dynamic_response')
logger.setLevel(logging.INFO)
file_handler = logging.handlers.RotatingFileHandler(
    LOG_FILE, maxBytes=10*1024*1024, backupCount=5
)
if jsonlogger:
    fmt = jsonlogger.JsonFormatter(
        '%(asctime)s %(levelname)s %(name)s %(bias)s %(attacker_ip)s %(message)s'
    )
    file_handler.setFormatter(fmt)
else:
    file_handler.setFormatter(
        logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s')
    )
logger.addHandler(file_handler)

# Prometheus metrics
RESPONSES_EXECUTED     = Counter('responses_executed', 'Total dynamic responses executed')
RESPONSES_SUCCESSFUL   = Counter('responses_successful', 'Successful dynamic responses')
RESPONSE_LATENCY       = Histogram('response_latency_seconds', 'Response latency')
ACTIVE_RESPONSES       = Gauge('active_responses', 'Active cognitive responses')
RESPONSE_HEALTH_STATUS = Gauge('response_health', 'Response health by type', ['response_type'])
# Track pending ES retry queue length
ELK_QUEUE_LENGTH      = Gauge('elk_retry_queue_length', 'Pending ES retry queue entries')

@dataclass
class DynamicResponse:
    """Representation of a single deception response event."""
    type: str
    bias: str
    attacker_ip: str
    timestamp: float
    parameters: Dict[str, Any]

# Load MITRE ATT&CK data for enrichment
if MitreAttackData:
    try:
        mitre_data = MitreAttackData(TTP_DATA_FILE)
    except Exception:
        mitre_data = None
else:
    mitre_data = None


def emit_event(event_type: str, data: Dict[str, Any]):
    """
    Emit structured event with optional TTP enrichment and resource metrics.
    Written as JSON to LOG_FILE for Filebeat or ingestion pipeline.
    """
    payload = {
        '@timestamp': datetime.utcnow().isoformat(),
        'event_type': event_type,
        **data
    }
    # Enrich with MITRE TTP info if available
    if mitre_data and data.get('ttp_match'):
        try:
            tech_obj = mitre_data.get_object_by_attack_id(data['ttp_match'], 'attack-p>            payload['mitre_technique_id']   = data['ttp_match']
            payload['mitre_technique_name'] = tech_obj.get('name')
        except Exception:
            pass
    # Add lightweight resource metrics
    try:
        import psutil
        payload['cpu_percent'] = psutil.cpu_percent()
        payload['mem_rss']     = psutil.Process().memory_info().rss
    except ImportError:
        pass
    logger.info(json.dumps(payload), extra={
        'bias': data.get('bias',''),
        

class DynamicResponseManager:
    """
    Main manager for dynamic honeypot orchestration and deception.
    """
    def __init__(self):
        self.docker_client   = docker.from_env()
        self.es_url          = f"http://{ES_HOST}:{ES_PORT}"
        self.response_templates = self._load_response_templates()
        self.attacker_state  = self._load_attacker_state()
        self.last_timestamps = {svc['name']: 0.0 for svc in HONEYPOTS}
        self._validate_services()
        logger.info('DynamicResponseManager initialized', extra={'bias':'init','attacker_ip':''})

    def _validate_services(self):
        for hp in HONEYPOTS:
            svc = hp['service']
            try:
                self.docker_client.services.get(svc)
                logger.info("Service '%s' is available", svc)
            except NotFound:
                logger.warning("Service '%s' not found during init", svc)
            except APIError as err:
                logger.error("Docker API error validating '%s': %s", svc, err)

    def _load_response_templates(self) -> Dict[str, List[Dict[str, Any]]]:
        return {
            'anchoring': [
                {'type':'misleading_info', 'message':'System vulnerable to CVE-2021-41773'},
                {'type':'fake_error',      'error':'Access Denied', 'hint':'Try admin:admin'}
            ],
            'confirmation': [
                {'type':'decoy_file','filename':'credentials.txt','content':'admin:password123'},
                {'type':'delayed_response','delay':5}
            ],
            'overconfidence': [
                {'type':'fake_success','message':'Access granted to /root','content':'Sensitive data found.'},
                {'type':'challenge','hint':'Bypass required for internal auth'}
            ]
        }

    def _load_attacker_state(self) -> Dict[str, Any]:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE,'r') as f:
                return json.load(f)
        return {}

    def _save_attacker_state(self):
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with open(STATE_FILE,'w') as f:
            json.dump(self.attacker_state, f, indent=2)

    def _update_attacker_profile(self, attacker_ip: str, bias: str, response_type: str):
        now = datetime.utcnow().isoformat()
        prof = self.attacker_state.get(attacker_ip, {
            'session_count':0,'bias_history':[],'response_history':[],
            'personality':'unknown','frustration_level':0.0,'confidence_drift':0.0
        })
        prof['session_count'] += 1
        prof['bias_history'].append(bias)
        prof['response_history'].append(response_type)
        prof['last_seen'] = now
        if response_type in ('fake_error','challenge'):
            prof['frustration_level'] += 0.1
        if response_type == 'fake_success':
            prof['confidence_drift'] += 0.2
        self.attacker_state[attacker_ip] = prof
        self._save_attacker_state()

    def fetch_recent_events(self) -> List[Tuple[str, Dict[str, Any]]]:
        results: List[Tuple[str, Dict[str, Any]]] = []
        for hp in HONEYPOTS:
            svc = hp['name']
            pattern = f"/home/student/dcd-unified/data/{svc}/logs/*.json"
            for path in sorted(__import__('glob').glob(pattern)):
                with open(path) as f:
                    for line in f:
                        try:
                            evt = json.loads(line)
                            ts = float(evt.get('timestamp', evt.get('time', 0)))
                            if ts <= self.last_timestamps[svc]:
                                continue
                            self.last_timestamps[svc] = max(self.last_timestamps[svc], ts)
                            ip = evt.get('src_ip') or evt.get('attacker_ip')
                            if ip:
                                results.append((ip, evt))
                        except json.JSONDecodeError:
                            continue
        return results

    def detect_bias(self, ip: str, event: Dict[str, Any]) -> str:
        scores = {'anchoring':0, 'confirmation':0, 'overconfidence':0}
        if event.get('username') and event.get('password'):
            scores['anchoring'] += 1
        if event.get('file_access') or event.get('filename'):
            scores['confirmation'] += 1
        if event.get('command'):
            cmd = event['command'].lower()
            if any(k in cmd for k in ['uname -a','sudo','rm -rf','nmap']):
                scores['overconfidence'] += 2
            else:
                scores['overconfidence'] += 1
        hist = self.attacker_state.get(ip, {}).get('bias_history', [])
        for b in hist[-5:]:
            scores[b] += 0.5
        return max(scores, key=scores.get)

    def trigger_honeypot(self, bias: str, attacker_ip: str) -> None:
        hps = [h for h in HONEYPOTS if h['bias']==bias]
        if not hps:
            logger.warning("No honeypot matches '%s' for '%s'", bias, attacker_ip)
            return
        svc = random.choice(hps)['service']
        try:
            service = self.docker_client.services.get(svc)
            rep = service.attrs['Spec']['Mode'].get('Replicated')
            if rep:
                curr = rep.get('Replicas',0)
                service.scale(curr+1)
                ACTIVE_RESPONSES.inc()
                logger.info(f"Scaled UP {svc}: {curr}→{curr+1}")
            else:
                logger.warning("Cannot scale non-replicated '%s'", svc)
        except Exception as e:
            logger.error(f"Error scaling {svc}: {e}")

    def apply_response(self, bias: str, attacker_ip: str) -> bool:
        start = time.time()
        tmpl = self.response_templates.get(bias, [])
        if not tmpl:
            logger.warning("No response templates for '%s'", bias)
            return False
        resp = random.choice(tmpl)
        rtype = resp['type']
        data = {'bias':bias,'attacker_ip':attacker_ip,'response_type':rtype}
        try:
            if rtype=='decoy_file':
                path = f"/home/student/dcd-unified/data/{bias}/{resp['filename']}"
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path,'w') as f: f.write(resp['content'])
            elif rtype=='delayed_response':
                time.sleep(resp['delay'])
            elif rtype=='misleading_info':
                pass
            # etc...
            self._update_attacker_profile(attacker_ip,bias,rtype)
            self.log_to_elasticsearch(attacker_ip,bias,rtype)
            RESPONSES_EXECUTED.inc()
            RESPONSES_SUCCESSFUL.inc()
            latency_ms = int((time.time()-start)*1000)
            ttp_id = RESPONSE_TTP_MAP.get(rtype) or None
            emit_event('apply_response',{**data,'latency_ms':latency_ms,'ttp_match':ttp_id})
            return True
        except:
            logger.exception("apply_response failed for '%s'", rtype)
            return False

    def log_to_elasticsearch(self, attacker_ip: str, bias: str, response_type: str):
        doc = {'@timestamp': datetime.utcnow().isoformat(), 'attacker_ip': attacker_ip, 'response.bias': bias, 'response.type': response_type}
        try:
            r = requests.post(f"{self.es_url}/dynamic-responses/_doc", json=doc, timeout=3)
            r.raise_for_status()
        except Exception as e:
            with open(ELK_QUEUE_FILE,'a') as f: f.write(json.dumps(doc)+"

# FastAPI setup for event-driven operation
app = FastAPI()
manager = DynamicResponseManager()

@app.post("/event")
async def on_event(req: Request):
    data = await req.json()
    bias = data.get("bias")
    ip   = data.get("attacker_ip")
    # offload blocking operations
    from fastapi.concurrency import run_in_threadpool
    await run_in_threadpool(manager.trigger_honeypot, bias, ip)
    result = await run_in_threadpool(manager.apply_response, bias, ip)
    return {"status": "ok" if result else "error"}

if __name__ == "__main__":
    # Expose Prometheus metrics on port 8000 (/metrics)
    start_http_server(8000)
    # Run FastAPI app via Uvicorn
    import uvicorn
    uvicorn.run(
        "dynamic_response:app",
        host="0.0.0.0",
        port=8080,
        log_level="info"
    )  and the updated script please
