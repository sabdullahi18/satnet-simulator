import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv("packet_delays.csv")
df['WasDelayed'] = df['WasDelayed'].astype(bool)
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))

# --- PLOT 1: SORTED LATENCY CURVE ---
sorted_df = df.sort_values('ActualDelay').reset_index(drop=True)
ax1.plot(sorted_df.index, sorted_df['ActualDelay'], color='blue', linewidth=2, label='Observed Delay')
ax1.fill_between(sorted_df.index, sorted_df['ActualDelay'], color='blue', alpha=0.1)
ax1.plot(sorted_df.index, sorted_df['MinDelay'], color='green', linestyle='--', label='Physical Min Delay')
ax1.set_title("Packet Latency Curve (Sorted)")
ax1.set_xlabel("Packet Rank (Fastest to Slowest)")
ax1.set_ylabel("Delay (seconds)")
ax1.legend()
ax1.grid(True, alpha=0.3)
threshold_idx = int(len(df) * 0.9)
ax1.axvline(threshold_idx, color='orange', linestyle=':', label='Top 10% (Spikes)')
ax1.text(threshold_idx, ax1.get_ylim()[1]*0.8, " Natural Spikes \n (Tail Latency)", color='orange')

# --- PLOT 2: HISTOGRAM ---
ax2.hist(df['ActualDelay'], bins=30, color='blue', alpha=0.7, edgecolor='black')
ax2.set_title("Distribution of Delays (Histogram)")
ax2.set_xlabel("Delay (seconds)")
ax2.set_ylabel("Frequency (Count)")
ax2.grid(True, alpha=0.3)

plt.tight_layout()
plt.show()
