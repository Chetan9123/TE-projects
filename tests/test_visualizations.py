import time
from dashboard.visualizations import summarize_traffic_for_plotly


def test_summarize_traffic_for_plotly_basic():
    now = time.time()
    pkts = [
        {"timestamp": now, "src_ip": "10.0.0.1", "dst_ip": "8.8.8.8", "length": 100},
        {"timestamp": now + 10, "src_ip": "10.0.0.1", "dst_ip": "8.8.8.8", "length": 200},
        {"timestamp": now + 70, "src_ip": "10.0.0.2", "dst_ip": "1.1.1.1", "length": 50},
    ]

    summary = summarize_traffic_for_plotly(pkts)
    # time_x and time_y should be present and length > 0
    assert "time_x" in summary and "time_y" in summary
    assert len(summary["time_x"]) >= 1
    assert len(summary["time_y"]) >= 1

    # top_src should contain our top IP
    top_src_ips = [e["ip"] for e in summary.get("top_src", [])]
    assert "10.0.0.1" in top_src_ips
