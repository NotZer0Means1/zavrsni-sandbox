"""Izvrsavanje nepouzdanog koda u efemernom, ocvrsnutom kontejneru.

Svako izvrsavanje dobiva vlastiti kontejner koji se unistava odmah nakon
zavrsetka. Kontejner se pokrece uz sljedeca ogranicenja:

  * runtime runc ili runsc (gVisor), ovisno o konfiguraciji
  * seccomp profil s popisom dopustenih sistemskih poziva
  * odbacene sve Linux ovlasti (cap_drop ALL) i no-new-privileges
  * korijenski datotecni sustav samo za citanje, /tmp kao tmpfs bez noexec
  * ogranicenja procesora, memorije i broja procesa preko cgroups
  * mreza iskljucena po zadanom
  * izvrsavanje kao neprivilegirani korisnik (nobody)
"""
from __future__ import annotations

import io
import logging
import tarfile
import time
import uuid
from typing import Optional, Tuple

import docker
from docker.errors import APIError, ContainerError, ImageNotFound, NotFound

from .config import Settings, settings as default_settings
from .models import ExecuteResponse, Mechanism, Verdict

log = logging.getLogger(__name__)

WORKDIR = "/sandbox"
SCRIPT_NAME = "main.py"

# Obrasci u stderr-u prema kojima se zakljucuje koji je mehanizam zaustavio radnju.
# Redoslijed je bitan: specificniji obrasci moraju doci prije opcenitih.
_MECHANISM_PATTERNS: Tuple[Tuple[str, Mechanism], ...] = (
    ("operation not permitted", Mechanism.CAPABILITIES),
    ("read-only file system", Mechanism.READ_ONLY_FS),
    ("cannot allocate memory", Mechanism.CGROUPS_MEMORY),
    ("resource temporarily unavailable", Mechanism.CGROUPS_PIDS),
    ("blockingioerror", Mechanism.CGROUPS_PIDS),
    ("temporary failure in name resolution", Mechanism.NETWORK_POLICY),
    ("network is unreachable", Mechanism.NETWORK_POLICY),
    ("name or service not known", Mechanism.NETWORK_POLICY),
    ("connection refused", Mechanism.NETWORK_POLICY),
    ("no route to host", Mechanism.NETWORK_POLICY),
    ("function not implemented", Mechanism.RUNTIME_KERNEL),
    ("bad system call", Mechanism.SECCOMP),
    ("permission denied", Mechanism.CAPABILITIES),
)


class InfrastructureError(RuntimeError):
    """Kvar orkestratora, a ne posljedica izvrsenog koda."""


def _tar_bytes(name: str, content: str) -> bytes:
    """Pakira izvorni kod u tar arhivu za prijenos u kontejner.

    Kod se upisuje prije pokretanja kontejnera, dok je zapisivanje jos dopusteno.
    Nakon pokretanja korijenski je datotecni sustav samo za citanje.
    """
    payload = content.encode("utf-8")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo(name=name)
        info.size = len(payload)
        info.mode = 0o444
        info.uid = 65534
        info.gid = 65534
        tar.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


def classify_mechanism(stderr: str, verdict: Verdict, oom: bool) -> Mechanism:
    """Odreduje koji je mehanizam izolacije zaustavio radnju.

    Klasifikacija se temelji na stanju kontejnera i porukama o pogreskama.
    Rezultat se biljezi uz svaki testni slucaj i cini osnovu za odgovor na IP2.
    """
    if oom:
        return Mechanism.CGROUPS_MEMORY
    if verdict is Verdict.TIMEOUT:
        return Mechanism.TIMEOUT
    if verdict is Verdict.OK:
        return Mechanism.NONE

    low = stderr.lower()
    for needle, mechanism in _MECHANISM_PATTERNS:
        if needle in low:
            return mechanism
    return Mechanism.NONE


class SandboxExecutor:
    """Orkestrator efemernih izvrsnih okruzenja."""

    def __init__(self, cfg: Optional[Settings] = None, client: Optional["docker.DockerClient"] = None):
        self.cfg = cfg or default_settings
        self.cfg.validate()
        self.client = client or docker.from_env()

    # ---------------------------------------------------------------- javno
    def execute(self, code: str, timeout_s: Optional[int] = None) -> ExecuteResponse:
        execution_id = uuid.uuid4().hex[:12]
        limits = self.cfg.limits
        timeout = timeout_s or limits.timeout_s

        container = None
        t_create = time.perf_counter()
        try:
            container = self._create_container(execution_id)
            container.put_archive(WORKDIR, _tar_bytes(SCRIPT_NAME, code))

            t_start = time.perf_counter()
            container.start()
            startup_ms = int((time.perf_counter() - t_start) * 1000)

            verdict, exit_code = self._wait(container, timeout)
            duration_ms = int((time.perf_counter() - t_create) * 1000)

            stdout, stderr = self._collect_output(container)
            oom = self._was_oom_killed(container)

            if oom:
                verdict = Verdict.OOM
            elif verdict is Verdict.OK and exit_code not in (0, None):
                verdict = Verdict.ERROR

            mechanism = classify_mechanism(stderr, verdict, oom)
            if verdict is Verdict.ERROR and mechanism is not Mechanism.NONE:
                verdict = Verdict.BLOCKED

            return ExecuteResponse(
                verdict=verdict,
                mechanism=mechanism,
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                duration_ms=duration_ms,
                startup_ms=startup_ms,
                runtime=self.cfg.runtime,
                profile=self.cfg.profile_name(),
                execution_id=execution_id,
            )
        except ImageNotFound as exc:
            raise InfrastructureError(f"slika {self.cfg.runner_image} ne postoji") from exc
        except (APIError, ContainerError) as exc:
            raise InfrastructureError(str(exc)) from exc
        finally:
            self._destroy(container)

    # ------------------------------------------------------------- interno
    def _create_container(self, execution_id: str):
        cfg, limits = self.cfg, self.cfg.limits

        security_opt = []
        if cfg.no_new_privileges:
            security_opt.append("no-new-privileges:true")
        if cfg.seccomp_profile:
            security_opt.append(f"seccomp={cfg.seccomp_path().read_text(encoding='utf-8')}")
        else:
            security_opt.append("seccomp=unconfined" if cfg.runtime == "runsc" else "seccomp=default")

        return self.client.containers.create(
            image=cfg.runner_image,
            name=f"sbx-{execution_id}",
            command=["python3", "-I", "-B", f"{WORKDIR}/{SCRIPT_NAME}"],
            runtime=cfg.runtime,
            working_dir=WORKDIR,
            user=cfg.run_as,
            network_mode=cfg.network_mode,
            network_disabled=cfg.network_mode == "none",
            read_only=cfg.read_only_rootfs,
            tmpfs={"/tmp": f"rw,noexec,nosuid,nodev,size={limits.tmpfs_mb}m"},
            mem_limit=f"{limits.memory_mb}m",
            memswap_limit=f"{limits.memory_mb}m",   # bez swapa: memorija je tvrda granica
            nano_cpus=limits.nano_cpus,
            pids_limit=limits.pids,
            cap_drop=["ALL"] if cfg.drop_all_caps else [],
            security_opt=security_opt,
            environment={
                "PYTHONUNBUFFERED": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
                "HOME": "/tmp",
            },
            labels={"sandbox.execution_id": execution_id, "sandbox.ephemeral": "true"},
            detach=True,
            stdin_open=False,
            tty=False,
        )

    def _wait(self, container, timeout: int) -> Tuple[Verdict, Optional[int]]:
        try:
            result = container.wait(timeout=timeout)
            return Verdict.OK, result.get("StatusCode")
        except Exception:
            # docker-py podize requests.ReadTimeout kad istekne vrijeme cekanja
            try:
                container.kill()
            except (APIError, NotFound):
                pass
            return Verdict.TIMEOUT, None

    def _collect_output(self, container) -> Tuple[str, str]:
        cap = self.cfg.limits.output_bytes
        try:
            out, err = container.logs(stdout=True, stderr=True, demux=True)
        except APIError:
            return "", ""

        def _decode(raw: Optional[bytes]) -> str:
            if not raw:
                return ""
            text = raw[:cap].decode("utf-8", errors="replace")
            if len(raw) > cap:
                text += f"\n... [izlaz skracen na {cap} bajtova]"
            return text

        return _decode(out), _decode(err)

    def _was_oom_killed(self, container) -> bool:
        try:
            container.reload()
            return bool(container.attrs.get("State", {}).get("OOMKilled"))
        except (APIError, NotFound):
            return False

    def _destroy(self, container) -> None:
        """Uklanja kontejner. Okruzenje je efemerno i ne smije prezivjeti zadatak."""
        if container is None:
            return
        try:
            container.remove(force=True, v=True)
        except (APIError, NotFound) as exc:
            log.warning("kontejner nije uklonjen: %s", exc)
