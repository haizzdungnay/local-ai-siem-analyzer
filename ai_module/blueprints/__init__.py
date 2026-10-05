"""ai_module/blueprints — Modular Flask route blueprints."""

from blueprints.ui import ui_bp
from blueprints.jobs import jobs_bp
from blueprints.ip_analysis import ip_analysis_bp
from blueprints.security_tests import security_tests_bp
from blueprints.notifications import notifications_bp
from blueprints.maintenance import maintenance_bp

__all__ = [
    "ui_bp",
    "jobs_bp",
    "ip_analysis_bp",
    "security_tests_bp",
    "notifications_bp",
    "maintenance_bp",
]
