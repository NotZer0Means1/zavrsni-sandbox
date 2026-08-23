# Izolirano cloud okruženje za izvršavanje koda AI agenata

Praktični dio završnog rada *Sigurnosna izolacija i sandboxing autonomnih AI agenata
u cloud okruženju*.

Sustav prima Python kod, izvršava ga u efemernom očvrsnutom kontejneru i vraća
rezultat zajedno s podatkom o tome je li neka radnja zaustavljena i koji ju je
mehanizam zaustavio.

## Stanje izrade

| Dio | Status |
|---|---|
| Orkestrator izvršavanja (`sandbox/app/executor.py`) | gotovo |
| Seccomp profil (`sandbox/profiles/`) | gotovo |
| Slika izvršnog okruženja (`Dockerfile.runner`) | gotovo |
| API sloj (`sandbox/app/main.py`) | gotovo |
| Revizijski zapis (`sandbox/app/audit.py`) | gotovo |
| Testni skup S1–S5 i ispitni okvir | gotovo |
| Autonomni agent (ReAct) + record/replay | gotovo |
| Pokus S6 – posredno ubacivanje uputa | gotovo |
| Terraform za AWS (eu-central-1) | gotovo |
| Mjerenje performansi + RedCode | gotovo |

## Arhitektura

```
korisnik ─ zadatak ─► autonomni agent (ReAct, model preko Ollame)
                          │   ▲
           generirani kod │   │ opažanje (rezultat izvršavanja)
                          ▼   │
                   orkestrator (Docker SDK)
                          │  stvara efemerni kontejner po izvršavanju
                          ▼
        ┌─────────────────────────────────┐
        │  izvršno okruženje              │
        │  runtime: runc ili runsc        │
        │  seccomp allowlist              │
        │  cap_drop ALL, no-new-privs     │
        │  rootfs read-only, /tmp tmpfs   │
        │  cgroups: CPU, RAM, PID         │
        │  mreža isključena               │
        │  korisnik nobody (65534)        │
        └─────────────────────────────────┘
                          │
                          ▼
                 revizijski zapis (JSONL)
```

Agent kod ne može pokrenuti drukčije nego kroz orkestrator, pa se sav generirani
kod nužno izvršava unutar izolacije. Model se poziva preko lokalne Ollame, uz
snimanje i reprodukciju odgovora (kaseta) radi ponovljivosti.

## Primijenjene mjere izolacije

| Mjera | Provedba | Sprječava (scenarij) |
|---|---|---|
| seccomp allowlist | `security_opt=seccomp=...` | S1 – bijeg preko sistemskih poziva jezgre |
| `cap_drop: ALL` + `no-new-privileges` | Docker API | S1, S5 – podizanje ovlasti |
| `read_only` rootfs + tmpfs `/tmp` | Docker API | S2 – izmjena datotečnog sustava |
| cgroups (RAM, CPU, PID) | `mem_limit`, `nano_cpus`, `pids_limit` | S4 – iscrpljivanje resursa |
| `network_mode=none` | Docker API | S3 – eksfiltracija, pristup 169.254.169.254 |
| neprivilegirani korisnik 65534 | `user=` | S1, S2 |
| efemerni kontejner | `remove(force=True)` | S5 – perzistencija |
| gVisor (`runsc`) | zamjena runtimea | S1 – ranjivosti jezgre domaćina |

Svaka se mjera može isključiti varijablom okruženja, što je nužno za odgovor na
IP2: usporedbom pokretanja istog napada s uključenom i isključenom pojedinom
mjerom utvrđuje se koji ga mehanizam stvarno zaustavlja.

## Pokretanje (lokalno)

```bash
cd sandbox
docker build -f Dockerfile.runner -t sandbox-runner:latest .
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Provjera:

```bash
curl -s localhost:8000/config | python3 -m json.tool
curl -s -X POST localhost:8000/execute \
     -H 'content-type: application/json' \
     -d '{"code":"print(2+2)"}'
```

Prebacivanje na gVisor (nakon što je `runsc` instaliran i registriran u
`/etc/docker/daemon.json`):

```bash
SBX_RUNTIME=runsc uvicorn app.main:app --port 8000
```

## Konfiguracija

| Varijabla | Zadano | Značenje |
|---|---|---|
| `SBX_RUNTIME` | `runc` | `runc` ili `runsc` (gVisor) |
| `SBX_SECCOMP` | `seccomp-strict.json` | prazno = Dockerov zadani profil |
| `SBX_NETWORK` | `none` | `none` ili ime Docker mreže |
| `SBX_READONLY` | `true` | rootfs samo za čitanje |
| `SBX_DROP_CAPS` | `true` | odbacivanje svih Linux ovlasti |
| `SBX_MEM_MB` | `256` | ograničenje memorije |
| `SBX_CPUS` | `0.5` | udio procesora |
| `SBX_PIDS` | `64` | najveći broj procesa |
| `SBX_TIMEOUT_S` | `10` | vremensko ograničenje izvršavanja |

## Napomena o sigurnosti

Repozitorij sadrži testne skripte koje namjerno pokušavaju probiti izolaciju.
Pokreću se isključivo u zasebnom okruženju namijenjenom ovom radu. Ne pokretati
na stroju koji sadrži osobne podatke niti na instanci s IAM ulogom koja ima
ovlasti šire od nužnih.
