"""RADIUS profile update and delete on the Classic REST route the controller UI uses.

The published Integration API serves RADIUS profiles GET-only (list_radius_profiles); the
create tool lives with the other VPN/RADIUS tools in ``vpn.py``. These two writes share the
site configuration CRUD core (``site_config``) and belong to the ``vpn`` tool family.
"""

from __future__ import annotations
