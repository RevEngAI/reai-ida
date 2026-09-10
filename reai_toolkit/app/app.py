from reai_toolkit.app.core import ConfigService, SimpleNetStore
from reai_toolkit.app.services.ai_decomp.ai_decomp_service import AiDecompService
from reai_toolkit.app.services.analysis_status.analysis_status import (
    AnalysisStatusService,
)
from reai_toolkit.app.services.auto_unstrip_status.auto_unstrip_status import (
    AutoUnstripStatusService,
)
from reai_toolkit.app.services.analysis_sync.analysis_sync import AnalysisSyncService
from reai_toolkit.app.services.auth.auth_service import AuthService
from reai_toolkit.app.services.chat.chat_service import ChatService
from reai_toolkit.app.services.existing_analyses.existing_analyses_service import (
    ExistingAnalysesService,
)
from reai_toolkit.app.services.matching.matching_service import MatchingService
from reai_toolkit.app.services.rename.rename_service import RenameService
from reai_toolkit.app.services.upload.upload_service import UploadService
from reai_toolkit.app.services.data_types.analysis_catalogue import AnalysisDataTypesService
from reai_toolkit.app.services.data_types.data_types_service import ImportDataTypesService
from reai_toolkit.app.services.variable_sync.variable_sync_service import VariableSyncService


class App:
    _ida_version: str = "UNKNOWN"
    _plugin_version: str = "UNKNOWN"

    def __init__(self, ida_version: str = "UNKNOWN", plugin_version: str = "UNKNOWN"):
        self._ida_version = ida_version
        self._plugin_version = plugin_version

        """Initialize the application."""
        self.config_service: ConfigService = ConfigService()
        self.netstore_service: SimpleNetStore = SimpleNetStore()
        self.auth_service: AuthService = AuthService(
            cfg=self.config_service,
            ida_version=self._ida_version,
            plugin_version=self._plugin_version,
        )
        sdk_config = self.auth_service.get_sdk_config()
        self.upload_service = UploadService(
            netstore_service=self.netstore_service,
            sdk_config=sdk_config,
        )
        self.analysis_status_service = AnalysisStatusService(
            netstore_service=self.netstore_service, sdk_config=sdk_config
        )
        self.auto_unstrip_status_service = AutoUnstripStatusService(
            netstore_service=self.netstore_service, sdk_config=sdk_config
        )
        self.data_types_service = ImportDataTypesService(
            netstore_service=self.netstore_service, sdk_config=sdk_config
        )
        self.rename_service = RenameService(
            netstore_service=self.netstore_service, sdk_config=sdk_config
        )
        self.data_types_catalogue = AnalysisDataTypesService(
            netstore_service=self.netstore_service, sdk_config=sdk_config
        )
        self.variable_sync_service = VariableSyncService(
            netstore_service=self.netstore_service,
            sdk_config=sdk_config,
            data_types_catalogue=self.data_types_catalogue,
        )
        self.analysis_sync_service = AnalysisSyncService(
            data_types_service=self.data_types_service,
            rename_service=self.rename_service,
            variable_sync_service=self.variable_sync_service,
            netstore_service=self.netstore_service, sdk_config=sdk_config
        )
        self.existing_analyses_service = ExistingAnalysesService(
            netstore_service=self.netstore_service, sdk_config=sdk_config
        )
        self.ai_decomp_service = AiDecompService(
            netstore_service=self.netstore_service, sdk_config=sdk_config
        )
        self.matching_service = MatchingService(
            netstore_service=self.netstore_service, sdk_config=sdk_config
        )
        self.chat_service = ChatService(
            netstore_service=self.netstore_service, sdk_config=sdk_config
        )

