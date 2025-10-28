# dashboard/routes.py
import os, json
from datetime import datetime
from flask import Blueprint, render_template, jsonify, Response
from flask import stream_with_context
import time
import json
from flask_login import login_required
from dashboard.visualizations import read_recent_packets, read_actions_log, read_rules_file, summarize_traffic_for_plotly

bp = Blueprint("dashboard", __name__, template_folder="templates", static_folder="static")

DEFAULT_PATHS = {
    "pcap_jsonl": "data/raw/packets.jsonl",
    "actions_log": "firewall_engine/logs/actions.log",
    "rules_json": "firewall_engine/logs/rules.json",
}


def register_routes(app):
    app.register_blueprint(bp)


@bp.route("/")
@login_required
def index():
    # pass a server-side timestamp to avoid template-formatting issues
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    return render_template("index.html", now=now)


@bp.route("/api/recent_traffic")
@login_required
def api_recent_traffic():
    pkts = read_recent_packets(DEFAULT_PATHS["pcap_jsonl"], n=200)
    summary = summarize_traffic_for_plotly(pkts)
    return jsonify({"packets": pkts, "summary": summary})


@bp.route("/api/actions")
@login_required
def api_actions():
    acts = read_actions_log(DEFAULT_PATHS["actions_log"], n=200)
    return jsonify({"actions": acts})


@bp.route("/api/rules")
@login_required
def api_rules():
    rules = read_rules_file(DEFAULT_PATHS["rules_json"])
    return jsonify({"rules": rules})


@bp.route('/stream/traffic')
@login_required
def stream_traffic():
    """Server-Sent Events endpoint that periodically streams the traffic summary
    as JSON. This enables simple "push" updates to the dashboard without a full
    websocket stack. The generator yields a JSON payload every 2 seconds.
    """
    def gen():
        while True:
            try:
                pkts = read_recent_packets(DEFAULT_PATHS["pcap_jsonl"], n=200)
                summary = summarize_traffic_for_plotly(pkts)
                payload = {"summary": summary, "packets": pkts}
                yield f"data: {json.dumps(payload)}\n\n"
            except Exception:
                # send an empty payload so client can handle it
                yield 'data: {"summary": {}}\n\n'
            time.sleep(2)

    return Response(stream_with_context(gen()), mimetype='text/event-stream')
