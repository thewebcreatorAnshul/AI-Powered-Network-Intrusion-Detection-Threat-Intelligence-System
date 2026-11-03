from pathlib import Path
from app.ingestion.pcap import PcapSourceAdapter

path = Path("../datasets/demo_syn_scan.pcap")
records = list(PcapSourceAdapter().iter_records(path))

print("Records:", len(records))
for record in records[:3]:
    print(record)
