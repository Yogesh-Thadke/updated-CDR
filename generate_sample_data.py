"""
Generate sample CDR data with IMEI and SMS columns for full feature demo.
Run: python generate_sample_data.py
"""
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random
import os

random.seed(42)
np.random.seed(42)

os.makedirs('data', exist_ok=True)

SUSPECT = '9876543210'
CONTACTS = [f'98{random.randint(10000000,99999999)}' for _ in range(15)]

# IMEIs — suspect uses 2 (SIM swap scenario)
SUSPECT_IMEI_1 = '352999000000001'
SUSPECT_IMEI_2 = '352999000000002'  # switched mid-month

# Mumbai-area cell towers
TOWERS = [
    (19.0760, 72.8777), (19.1136, 72.8697), (19.0330, 72.8453),
    (18.9254, 72.8242), (19.2183, 72.9781), (19.0728, 72.8826),
    (19.1487, 72.9019), (18.9633, 72.8356)
]

records = []
record_id = 1
start_date = datetime(2024, 1, 1)

for day in range(30):
    current_date = start_date + timedelta(days=day)
    # Spike on day 15
    n_calls = 15 if day == 15 else random.randint(2, 6)
    # IMEI switches on day 16
    imei = SUSPECT_IMEI_1 if day < 16 else SUSPECT_IMEI_2

    for _ in range(n_calls):
        hour = random.choices(range(24), weights=[2,3,1,1,1,2,4,8,10,10,9,8,8,9,9,8,7,7,7,6,5,4,3,2])[0]
        # Odd-hour calls in first week
        if day < 7 and random.random() < 0.3:
            hour = random.randint(0, 4)

        call_time = current_date.replace(
            hour=hour, minute=random.randint(0,59), second=random.randint(0,59)
        )
        contact = random.choice(CONTACTS)
        is_outgoing = random.random() > 0.45
        call_type = random.choices(['Outgoing','Incoming','Missed'], weights=[5,4,1])[0]
        record_type = random.choices(['Call','SMS'], weights=[8,2])[0]
        duration = 0 if call_type == 'Missed' else (random.randint(0,4) if random.random()<0.15 else random.randint(10,600))
        if record_type == 'SMS':
            duration = 0
        tower = random.choice(TOWERS)

        records.append({
            'record_id': record_id,
            'caller_number': SUSPECT if is_outgoing else contact,
            'receiver_number': contact if is_outgoing else SUSPECT,
            'call_type': call_type,
            'record_type': record_type,
            'start_time': call_time.strftime('%Y-%m-%d %H:%M:%S'),
            'duration_seconds': duration,
            'cell_tower_lat': tower[0] + random.uniform(-0.015, 0.015),
            'cell_tower_lon': tower[1] + random.uniform(-0.015, 0.015),
            'imei': imei
        })
        record_id += 1

# Calls between contacts (richer network graph)
for _ in range(50):
    c1, c2 = random.sample(CONTACTS, 2)
    day = random.randint(0, 29)
    call_time = start_date + timedelta(days=day, hours=random.randint(8,22), minutes=random.randint(0,59))
    tower = random.choice(TOWERS)
    records.append({
        'record_id': record_id,
        'caller_number': c1,
        'receiver_number': c2,
        'call_type': random.choice(['Outgoing','Incoming']),
        'record_type': 'Call',
        'start_time': call_time.strftime('%Y-%m-%d %H:%M:%S'),
        'duration_seconds': random.randint(10, 300),
        'cell_tower_lat': tower[0] + random.uniform(-0.015, 0.015),
        'cell_tower_lon': tower[1] + random.uniform(-0.015, 0.015),
        'imei': f'35299900000{random.randint(10,99)}'
    })
    record_id += 1

df = pd.DataFrame(records).sort_values('start_time').reset_index(drop=True)
df.to_csv('data/sample_cdr_data.csv', index=False)
print(f"✅ Generated {len(df)} records")
print(f"   Suspect:  {SUSPECT}")
print(f"   Contacts: {CONTACTS[:5]}...")
print(f"   IMEI 1:   {SUSPECT_IMEI_1} (days 1-15)")
print(f"   IMEI 2:   {SUSPECT_IMEI_2} (days 16-30) ← SIM swap scenario")
print(f"   SMS records: {df[df['record_type']=='SMS'].shape[0]}")
print(f"   Call records: {df[df['record_type']=='Call'].shape[0]}")
