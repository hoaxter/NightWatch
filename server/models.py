from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, ForeignKey, JSON
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class Agent(Base):
    __tablename__ = 'agents'
    id = Column(Integer, primary_key=True)
    hostname = Column(String, unique=True, nullable=False)
    ip_address = Column(String)
    os_info = Column(String)
    last_seen = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="offline") # online, offline
    alerts = relationship("Alert", back_populates="agent")

class Rule(Base):
    __tablename__ = 'rules'
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    description = Column(String)
    severity = Column(String, default="medium") # low, medium, high, critical
    enabled = Column(Boolean, default=True)
    rule_type = Column(String) # process, network, file, log
    conditions = Column(JSON, nullable=False) # JSON logic for matching
    # Example condition: {"field": "process.name", "op": "eq", "value": "mimikatz.exe"}

class Alert(Base):
    __tablename__ = 'alerts'
    id = Column(Integer, primary_key=True)
    agent_id = Column(Integer, ForeignKey('agents.id'))
    rule_id = Column(Integer, ForeignKey('rules.id'), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    severity = Column(String)
    title = Column(String)
    description = Column(Text)
    details = Column(JSON) # Snapshot data that triggered it
    status = Column(String, default="new") # new, in_progress, resolved, ignored
    
    agent = relationship("Agent", back_populates="alerts")
    rule = relationship("Rule")
