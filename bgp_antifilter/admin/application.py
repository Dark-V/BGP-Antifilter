"""Compose admin services without constructing an HTTP server."""

from .actions import ActionsService
from .auth import AuthService
from .config import AdminConfig
from .diagnostics import DiagnosticsService
from .lists import ListService
from .settings import SettingsService
from .status import StatusService
from .updates import UpdatesService
from .backups import BackupService
from .dns_proxy import DnsProxyService


class AdminApplication:
    def __init__(self, config=None):
        self.config = AdminConfig.from_env() if config is None else config
        self.settings = SettingsService(self.config)
        self.dns_proxy = DnsProxyService(self.config, self.settings)
        self.auth = AuthService()
        self.actions = ActionsService(self.config, self.settings, self.dns_proxy)
        self.diagnostics = DiagnosticsService(self.settings)
        self.lists = ListService(self.config)
        self.backups = BackupService(self.config, self.settings, self.lists)
        self.status = StatusService(self.config, self.settings, self.actions)
        self.updates = UpdatesService(self.settings)
