from fastapi import FastAPI
from pydantic import BaseModel
import redis
import json
import time

app = FastAPI(title="AI-NOC Ingestion API")
redis_client = redis.Redis(host='redis', port=6379, db=0, decode_responses=True)

class LogMessage(BaseModel):
    device_name: str
    message: str
    timestamp: str

@app.post("/ingest/logs")
async def ingest_logs(log: LogMessage):
    redis_client.lpush("log_queue", json.dumps(log.dict()))
    return {"status": "success"}

# =========================================================
# MAGIC BUTTONS 1-7: METRICS (For Isolation Forest)
# =========================================================

@app.post("/ingest/simulate/normal")
async def simulate_normal():
    data = {"device_name": "Switch-01", "flow_duration": 15.0, "fwd_pkts_tot": 8.0, "bwd_pkts_tot": 8.0, "timestamp": str(time.time())}
    redis_client.lpush("metric_queue", json.dumps(data))
    return {"status": "success", "message": "1. Normal traffic queued!"}

@app.post("/ingest/simulate/ddos")
async def simulate_ddos():
    data = {"device_name": "Core-Router-01", "flow_duration": 9999999.0, "fwd_pkts_tot": 85000.0, "bwd_pkts_tot": 90000.0, "timestamp": str(time.time())}
    redis_client.lpush("metric_queue", json.dumps(data))
    return {"status": "success", "message": "2. Hikari DDoS metric queued!"}

@app.post("/ingest/simulate/probing")
async def simulate_probing():
    data = {"device_name": "Firewall-Ext", "flow_duration": 500.0, "fwd_pkts_tot": 1000.0, "bwd_pkts_tot": 2.0, "timestamp": str(time.time())}
    redis_client.lpush("metric_queue", json.dumps(data))
    return {"status": "success", "message": "3. Probing attack queued!"}

@app.post("/ingest/simulate/botnet")
async def simulate_botnet():
    data = {"device_name": "Server-Web", "flow_duration": 80000.0, "fwd_pkts_tot": 400.0, "bwd_pkts_tot": 400.0, "timestamp": str(time.time())}
    redis_client.lpush("metric_queue", json.dumps(data))
    return {"status": "success", "message": "4. Botnet activity queued!"}

@app.post("/ingest/simulate/crypto-miner")
async def simulate_crypto():
    data = {"device_name": "Database-01", "flow_duration": 999999.0, "fwd_pkts_tot": 50.0, "bwd_pkts_tot": 50.0, "timestamp": str(time.time())}
    redis_client.lpush("metric_queue", json.dumps(data))
    return {"status": "success", "message": "5. Crypto-Miner traffic queued!"}

@app.post("/ingest/simulate/data-leak")
async def simulate_data_leak():
    data = {"device_name": "File-Server", "flow_duration": 50.0, "fwd_pkts_tot": 10.0, "bwd_pkts_tot": 99999.0, "timestamp": str(time.time())}
    redis_client.lpush("metric_queue", json.dumps(data))
    return {"status": "success", "message": "6. Data Exfiltration queued!"}

@app.post("/ingest/simulate/ping-flood")
async def simulate_ping_flood():
    data = {"device_name": "Gateway-01", "flow_duration": 5.0, "fwd_pkts_tot": 10000.0, "bwd_pkts_tot": 10000.0, "timestamp": str(time.time())}
    redis_client.lpush("metric_queue", json.dumps(data))
    return {"status": "success", "message": "7. Ping Flood queued!"}

# =========================================================
# MAGIC BUTTONS 8-10: TEXT LOGS (For DistilBERT)
# =========================================================

@app.post("/ingest/simulate/brute-force")
async def simulate_brute_force():
    data = {"device_name": "Auth-Server", "message": "CRITICAL: Multiple failed password attempts for Admin root account.", "timestamp": str(time.time())}
    redis_client.lpush("log_queue", json.dumps(data))
    return {"status": "success", "message": "8. Brute-Force Log queued!"}

@app.post("/ingest/simulate/sql-injection")
async def simulate_sql_injection():
    data = {"device_name": "Web-App", "message": "ERROR: SQL syntax error near 'DROP TABLE users' on login portal.", "timestamp": str(time.time())}
    redis_client.lpush("log_queue", json.dumps(data))
    return {"status": "success", "message": "9. SQL Injection Log queued!"}

@app.post("/ingest/simulate/safe-log")
async def simulate_safe_log():
    data = {"device_name": "Mail-Server", "message": "INFO: User JohnDoe successfully logged in from recognized IP.", "timestamp": str(time.time())}
    redis_client.lpush("log_queue", json.dumps(data))
    return {"status": "success", "message": "10. Safe Log queued!"}