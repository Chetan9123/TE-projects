import os
import time
import json
import tempfile

from data_collection.store_raw_data import DataStore


def test_datastore_save_and_tail_jsonl():
    with tempfile.TemporaryDirectory() as td:
        ds = DataStore(out_dir=td)
        pkt = {"timestamp": time.time(), "src_ip": "1.2.3.4", "dst_ip": "8.8.8.8", "length": 123}
        ds.save_packet(pkt)

        jsonl_path = os.path.join(td, "packets.jsonl")
        assert os.path.exists(jsonl_path)

        items = ds.tail_jsonl(1)
        assert isinstance(items, list)
        assert len(items) == 1
        assert items[0]["src_ip"] == pkt["src_ip"]
