import json

class DetectionEngine:
    def __init__(self, db_session):
        self.db = db_session

    def evaluate(self, telemetry, agent_id):
        """
        Evaluate telemetry against enabled rules.
        telemetry: dict containing 'type' (process, network, file) and 'data' (dict)
        """
        from server.models import Rule, Alert
        
        # Fetch enabled rules
        rules = self.db.query(Rule).filter_by(enabled=True).all()
        alerts = []

        for rule in rules:
            if self._matches(rule, telemetry):
                alert = Alert(
                    agent_id=agent_id,
                    rule_id=rule.id,
                    severity=rule.severity,
                    title=f"Rule Match: {rule.name}",
                    description=rule.description,
                    details=telemetry['data'],
                    status="new"
                )
                alerts.append(alert)
        
        return alerts

    def _matches(self, rule, telemetry):
        if rule.rule_type != telemetry.get('type'):
            return False

        conditions = rule.conditions
        data = telemetry.get('data', {})

        # Special handling for Hash Reputation
        if rule.rule_type == 'hash_reputation':
            # Check if the telemetry has a hash that is in the blacklist
            # For this demo, we assume the rule condition contains the blacklist or we check a global list
            # Let's assume the rule has a "value" which is the bad hash
            telemetry_hash = data.get('hash')
            if not telemetry_hash:
                return False
            
            # If rule is "Malicious Hash", we check if telemetry hash matches
            cond_list = conditions if isinstance(conditions, list) else [conditions]
            for cond in cond_list:
                if cond.get('field') == 'hash' and cond.get('value') == telemetry_hash:
                    return True
            return False

        # Standard Logic
        cond_list = conditions if isinstance(conditions, list) else [conditions]

        for cond in cond_list:
            field = cond.get('field')
            op = cond.get('op')
            val = cond.get('value')

            # Resolve field value from data (dot notation support)
            data_val = self._get_field_value(data, field)
            
            if not self._check_condition(data_val, op, val):
                return False
        
        return True

    def _get_field_value(self, data, field_path):
        parts = field_path.split('.')
        curr = data
        for p in parts:
            if isinstance(curr, dict):
                curr = curr.get(p)
            else:
                return None
        return curr

    def _check_condition(self, data_val, op, rule_val):
        if data_val is None:
            return False
            
        data_val = str(data_val).lower()
        rule_val = str(rule_val).lower()

        if op == 'eq':
            return data_val == rule_val
        elif op == 'neq':
            return data_val != rule_val
        elif op == 'contains':
            return rule_val in data_val
        elif op == 'startswith':
            return data_val.startswith(rule_val)
        elif op == 'endswith':
            return data_val.endswith(rule_val)
        
        return False
