import json
import datetime


start_dt = datetime.datetime(2025, 9, 16, 15, 30, 0)
start_ts_ms = int(start_dt.timestamp() * 1000)


num_frames = 10000  


def make_phases(veh_state):
    return [
        {"phase": 1, "state": {"veh": veh_state, "ped": "NA"}},
        {"phase": 2, "state": {"veh": "R", "ped": "NA"}},
        {"phase": 3, "state": {"veh": "R", "ped": "NA"}},
        {"phase": 4, "state": {"veh": "R", "ped": "NA"}},
        {"phase": 5, "state": {"veh": "R", "ped": "NA"}},
        {"phase": 6, "state": {"veh": veh_state, "ped": "NA"}},
        {"phase": 7, "state": {"veh": "R", "ped": "NA"}},
        {"phase": 8, "state": {"veh": "R", "ped": "NA"}},
    ]


with open("phases.ndjson", "w") as f:
    for i in range(num_frames):
        ts_ms = start_ts_ms + i * 10_000 
        veh_state = "G" if i % 2 == 0 else "Y" 
        msg = {
            "ts_ms": ts_ms,
            "type": "phase",
            "phases": make_phases(veh_state),
        }
        f.write(json.dumps(msg, separators=(",", ":")) + "\n")

print("生成 phases.ndjson 完成")
