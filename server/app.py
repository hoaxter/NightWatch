from flask import Flask, request, jsonify, render_template
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os

from server.models import Base, Agent, Rule, Alert
from server.engine import DetectionEngine

app = Flask(__name__)

# Database Setup
DB_PATH = 'sqlite:///edr.db'
engine = create_engine(DB_PATH, connect_args={'check_same_thread': False})
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
session = Session()

# Initialize Detection Engine
detection_engine = DetectionEngine(session)

# Seed some default rules if empty
if session.query(Rule).count() == 0:
    defaults = [
        Rule(name="Suspicious Process Chain (Office->Cmd)", 
             description="Word or Excel spawning Command Prompt",
             severity="high", rule_type="process",
             conditions=[
                 {"field": "parent_name", "op": "contains", "value": "winword.exe"},
                 {"field": "name", "op": "eq", "value": "cmd.exe"}
             ]),
        Rule(name="Suspicious PowerShell (Encoded)", 
             description="PowerShell with encoded command",
             severity="critical", rule_type="process",
             conditions=[
                 {"field": "name", "op": "contains", "value": "powershell"},
                 {"field": "cmdline", "op": "contains", "value": "-enc"}
             ]),
        Rule(name="Mimikatz Detection", 
             description="Known credential dumper",
             severity="critical", rule_type="process",
             conditions={"field": "name", "op": "contains", "value": "mimikatz"}),
        Rule(name="Suspicious Port 4444", 
             description="Common Metasploit port",
             severity="high", rule_type="network",
             conditions={"field": "raddr", "op": "contains", "value": ":4444"}),
        Rule(name="Suspicious File in Downloads", 
             description="Executable dropped in Downloads",
             severity="medium", rule_type="file",
             conditions=[
                 {"field": "path", "op": "contains", "value": "Downloads"},
                 {"field": "path", "op": "endswith", "value": ".exe"}
             ]),
        Rule(name="Known Malicious Hash", 
             description="File matches known malware hash",
             severity="critical", rule_type="hash_reputation",
             conditions={"field": "hash", "op": "eq", "value": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"}), # Example Hash
    ]
    session.add_all(defaults)
    session.commit()

@app.route('/')
def index():
    return render_template('index.html')

# --- API for Agents ---

@app.route('/api/register', methods=['POST'])
def register_agent():
    data = request.json
    hostname = data.get('hostname')
    ip = data.get('ip')
    os_info = data.get('os')

    agent = session.query(Agent).filter_by(hostname=hostname).first()
    if not agent:
        agent = Agent(hostname=hostname, ip_address=ip, os_info=os_info, status="online")
        session.add(agent)
    else:
        agent.ip_address = ip
        agent.os_info = os_info
        agent.last_seen = datetime.utcnow()
        agent.status = "online"
    
    session.commit()
    return jsonify({"status": "registered", "id": agent.id})

@app.route('/api/telemetry', methods=['POST'])
def ingest_telemetry():
    data = request.json
    agent_id = data.get('agent_id')
    telemetry_batch = data.get('events', []) # List of events

    agent = session.query(Agent).get(agent_id)
    if agent:
        agent.last_seen = datetime.utcnow()
        agent.status = "online"
    
    new_alerts = []
    for event in telemetry_batch:
        # Event structure: {type: "process", data: {...}}
        alerts = detection_engine.evaluate(event, agent_id)
        for alert in alerts:
            session.add(alert)
            new_alerts.append(alert.title)
    
    session.commit()
    return jsonify({"status": "processed", "alerts_generated": len(new_alerts)})

@app.route('/api/rules', methods=['GET'])
def get_rules():
    rules = session.query(Rule).filter_by(enabled=True).all()
    return jsonify([{
        "id": r.id,
        "name": r.name,
        "type": r.rule_type,
        "conditions": r.conditions
    } for r in rules])

# --- API for UI ---

@app.route('/api/ui/stats')
def ui_stats():
    total_agents = session.query(Agent).count()
    online_agents = session.query(Agent).filter_by(status="online").count()
    active_alerts = session.query(Alert).filter(Alert.status.in_(['new', 'in_progress'])).count()
    critical_alerts = session.query(Alert).filter_by(severity='critical', status='new').count()
    
    return jsonify({
        "total_agents": total_agents,
        "online_agents": online_agents,
        "active_alerts": active_alerts,
        "critical_alerts": critical_alerts
    })

@app.route('/api/ui/alerts')
def ui_alerts():
    alerts = session.query(Alert).order_by(Alert.timestamp.desc()).limit(50).all()
    return jsonify([{
        "id": a.id,
        "title": a.title,
        "severity": a.severity,
        "agent": a.agent.hostname if a.agent else "Unknown",
        "timestamp": a.timestamp.isoformat(),
        "status": a.status,
        "description": a.description,
        "details": a.details
    } for a in alerts])

@app.route('/api/ui/agents')
def ui_agents():
    agents = session.query(Agent).all()
    return jsonify([{
        "id": a.id,
        "hostname": a.hostname,
        "ip": a.ip_address,
        "status": a.status,
        "last_seen": a.last_seen.isoformat(),
        "os": a.os_info
    } for a in agents])

@app.route('/api/ui/alerts/<int:alert_id>/status', methods=['POST'])
def update_alert_status(alert_id):
    data = request.json
    new_status = data.get('status')
    alert = session.query(Alert).get(alert_id)
    if alert:
        alert.status = new_status
        session.commit()
        return jsonify({"success": True})
    return jsonify({"success": False}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
