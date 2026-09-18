"""Import-time application initialization must never touch a running service workspace."""

import os
import tempfile

# Set before test modules import service.app. Individual tests still use tmp_path.
os.environ["SCA_WORKSPACE"] = tempfile.mkdtemp(prefix="sca-pytest-workspace-")
