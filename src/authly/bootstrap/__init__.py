"""
Bootstrap module for Authly authentication service.

This module provides system initialization and seeding functionality
for setting up the initial state of an Authly instance.
"""

from .admin_seeding import bootstrap_admin_system, bootstrap_admin_user, register_admin_scopes

__all__ = ["bootstrap_admin_system", "bootstrap_admin_user", "register_admin_scopes"]
