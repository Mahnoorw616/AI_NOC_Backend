import redis
import json
import time
import joblib
import warnings
from transformers import pipeline

warnings.filterwarnings("ignore")
print("🛡️ Security Worker is waking up...")
 
# 1. LOAD THE REAL HIKARI BRAIN (Isolation Forest + Profiles)
print("🧠 Loading the trained Hikari 2021 AI Brain...")
try:
    saved_brain = joblib.load("hikari_ai_brain.pkl")
    math_ai = saved_brain['model']
    attack_profiles = saved_brain['profiles']
except FileNotFoundError:
    print("❌ ERROR: 'hikari_ai_brain.pkl' not found. Did you run train_ai.py first?")
    exit()

# Helper Function: Name the attack using learned patterns
def identify_attack(flow, fwd, bwd):
    best_match = "Unknown Hikari Anomaly"
    min_dist = float('inf')
    for attack_name, features in attack_profiles.items():
        # Find which attack fingerprint matches these numbers closest
        dist = abs(features['flow_duration'] - flow) + abs(features['fwd_pkts_tot'] - fwd) + abs(features['bwd_pkts_tot'] - bwd)
        if dist < min_dist:
            min_dist = dist
            best_match = attack_name
    return best_match
  
# 2. WAKE UP THE TEXT AI 
print("📖 Waking up Language AI (DistilBERT)...")
text_ai = pipeline("text-classification", model="distilbert-base-uncased-finetuned-sst-2-english")
 
# 3. CONNECT TO REDIS 
redis_client = redis.Redis(host='redis', port=6379, db=0, decode_responses=True)
print("✅ Worker fully awake and connected to Redis! Waiting for data...")
 
# 4. INFINITE LOOP (The guard never sleeps) 
while True:
    queue_name, message_data = redis_client.brpop(["log_queue", "metric_queue"])
    data = json.loads(message_data)
    
    # --- SCENARIO A: NUMBERS (Hikari Attack Detection) ---
    if queue_name == "metric_queue":
        print(f"\n📊 Analyzing Network Traffic from {data['device_name']}...")
        
        flow = float(data['flow_duration'])
        fwd = float(data['fwd_pkts_tot'])
        bwd = float(data['bwd_pkts_tot'])
        
        # Isolation Forest asks: Is this normal [1] or an attack [-1]?
        prediction = math_ai.predict([[flow, fwd, bwd]])[0]
        
        if prediction == 1:
            print("   ✅ Traffic looks perfectly normal.")
        else:
            # We found an anomaly! Let's match it to the learned attack patterns
            attack_name = identify_attack(flow, fwd, bwd)
            print(f"   🚨 THREAT DETECTED: Network Anomaly!")
            print(f"   🔍 Hikari Signature Match -> [{attack_name}]")
            print("   -> (Next Step: Save to Database Vault)")

    # --- SCENARIO B: TEXT (Log Analysis) ---
    elif queue_name == "log_queue":
        print(f"\n📝 Analyzing Text Log from {data['device_name']}...")
        
        message_text = data['message']
        ai_result = text_ai(message_text)[0] 
        
        label = ai_result['label']
        score = ai_result['score']
        
        if label == "NEGATIVE" and score > 0.90:
            print(f"   🚨 THREAT DETECTED in Text! (Certainty: {score * 100:.1f}%)")
            print(f"   -> Text flagged: '{message_text}'")
            print("   -> (Next Step: Save to Database Vault)")
        else:
            print(f"   ✅ Log text seems safe. (Certainty: {score * 100:.1f}%)")

    time.sleep(1)