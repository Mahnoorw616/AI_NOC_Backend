import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
import warnings

# Ignore version warnings
warnings.filterwarnings("ignore")

print("🏫 Welcome to the AI Police Academy!")
print("📖 Opening the hikari_2021.csv dataset... (This might take a minute)")

try:
    dataset = pd.read_csv("hikari_2021.csv")
except FileNotFoundError:
    print("❌ ERROR: Could not find 'hikari_2021.csv'. Make sure it is in your folder!")
    exit()

# 1. CLEAN UP COLUMN NAMES (Removes invisible spaces)
dataset.columns = dataset.columns.str.strip()

# 2. THE EXCEL BUG FIX: Smart Column Detection
# It checks for both the cut-off name AND the full name
if 'traffic_category' in dataset.columns:
    cat_col = 'traffic_category'
elif 'traffic_cat' in dataset.columns:
    cat_col = 'traffic_cat'
else:
    print(f"❌ ERROR: Cannot find traffic category. Available columns are: {list(dataset.columns)}")
    exit()

if 'Label' in dataset.columns:
    label_col = 'Label'
elif 'label' in dataset.columns:
    label_col = 'label'
else:
    print(f"❌ ERROR: Cannot find Label. Available columns are: {list(dataset.columns)}")
    exit()

features_to_study =['flow_duration', 'fwd_pkts_tot', 'bwd_pkts_tot']

for feature in features_to_study:
    if feature not in dataset.columns:
        print(f"❌ ERROR: Column '{feature}' not found! Available columns are: {list(dataset.columns)}")
        exit()

# 3. Drop rows with missing data to prevent crashes
clean_dataset = dataset.dropna(subset=features_to_study +[cat_col, label_col])

# 4. TRAIN THE AI (Isolation Forest) ON NORMAL TRAFFIC
print("🧠 Training the Isolation Forest on healthy network traffic...")
normal_data = clean_dataset[clean_dataset[label_col] == 0]
math_ai = IsolationForest(contamination=0.01, random_state=42)
math_ai.fit(normal_data[features_to_study].values)

# 5. CREATE ATTACK FINGERPRINTS
print("🔍 Learning the specific patterns of Hikari attacks...")
attack_data = clean_dataset[clean_dataset[label_col] == 1]
# We group by the dynamic category column name we found earlier
attack_profiles = attack_data.groupby(cat_col)[features_to_study].median().to_dict('index')

# 6. HAND OUT THE DIPLOMA
print("🎓 Training complete! Saving the AI's brain and profiles...")
saved_brain = {
    'model': math_ai,
    'profiles': attack_profiles
}
joblib.dump(saved_brain, "hikari_ai_brain.pkl")

print("✅ DONE! The brain is saved as 'hikari_ai_brain.pkl'. Ready for Docker!")