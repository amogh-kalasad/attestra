"""Vulnerability intelligence: validated KEV/EPSS feed store, freshness, CVSS 4.0, NVD and OSV.

Everything here is offline-safe: parsers and validators take bytes, and network fetches
live only in :mod:`attestra.ops.feeds` (operator-triggered). A failed or corrupt feed
never replaces the last good copy on disk.
"""
# @lat: [[intel-and-reporting]]
