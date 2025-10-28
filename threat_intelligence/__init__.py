# threat_intelligence/__init__.py
"""
Threat Intelligence module for AI-NGFW.

Automates fetching, parsing, and updating firewall rules
from global and local threat intelligence sources.
"""
__all__ = ["feed_fetcher", "parser", "rule_updater", "threat_analyzer"]
