"""Builder-runner configuration.

Deliberately tiny. This sidecar does one thing — drive the builder, the imager
and the provisioning stack over the Docker socket — and holds no identity, no
sessions and no users. Who may ask for a build, and what gets written to the
audit log when they do, is the backend's business and is settled before a
request reaches here.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="", extra="ignore")

    # Absolute path to the project ON THE HOST. Sibling containers are started
    # through the Docker socket, so their bind-mount paths are resolved by the
    # daemon against the host filesystem, not against this container's. Leave it
    # empty: it is detected from this container's own /project mount, which is
    # always right. Set it only to override that detection.
    host_project_dir: str = ""
    # Path to the project inside THIS container. Used to read output/ and as the
    # `docker build` context, which the docker CLI resolves in here.
    project_dir: str = "/project"

    # The base URL machines in the field use to reach the control plane. The
    # provisioning stack is rendered with it, so it has to be known here too.
    control_url: str = ""

    @property
    def output_dir(self) -> str:
        return f"{self.project_dir}/output"


settings = Settings()
