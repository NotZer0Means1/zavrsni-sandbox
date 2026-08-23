# Postavljanje i pokretanje na AWS-u (eu-central-1)

Uputa vodi od praznog AWS računa do gotovih tablica rezultata. Cijeli je postupak
oko 30 minuta, od čega je većina čekanje. Trošak je zanemariv: instanca m7i-flex.large
u eu-central-1 stoji približno 0,096 USD na sat, a cijelo testiranje traje 1–2 sata.

> VAŽNO: na kraju obavezno pokrenuti `terraform destroy` (korak 8). Instanca
> troši novac dok god postoji.

---

## Preduvjeti (na tvom računalu, jednokratno)

Trebaš tri alata i jedan AWS račun.

1. **AWS račun** s IAM korisnikom koji ima ovlasti za EC2, IAM i CloudWatch.
2. **AWS CLI** — https://aws.amazon.com/cli/ . Nakon instalacije:
   ```
   aws configure
   ```
   Upisati Access Key, Secret Key, regiju `eu-central-1` i format `json`.
   Provjera: `aws sts get-caller-identity` mora ispisati tvoj račun.
3. **Terraform** — https://developer.hashicorp.com/terraform/install .
   Provjera: `terraform version`.
4. **Git** — za slanje koda na GitHub.

---

## Korak 1 — kod na GitHub

Na GitHubu napravi repozitorij (može privatan), npr. `zavrsni-sandbox`. Zatim iz
mape projekta na svom računalu (PowerShell je dovoljan, ovdje ne treba Linux):

```
cd C:\Users\vovas\thesis\projekt
git init
git add .
git commit -m "Prakticni dio zavrsnog rada"
git branch -M main
git remote add origin https://github.com/<tvoje-ime>/zavrsni-sandbox.git
git push -u origin main
```

Provjeri `git status` prije slanja: datoteka `infra/terraform.tfvars` NE SMIJE biti
na popisu (sadrži tvoju IP adresu i ime ključa). `.gitignore` je već izuzima.

Ako je repo privatan, pri kloniranju na instanci trebat će Personal Access Token.
Najjednostavnije: drži repo javnim dok traju mjerenja, pa ga vrati na privatno.

---

## Korak 2 — EC2 ključ za SSH

Ako već nemaš ključ u regiji eu-central-1, napravi ga:

```
aws ec2 create-key-pair --region eu-central-1 --key-name sandbox-key \
    --query KeyMaterial --output text > sandbox-key.pem
```

Na Windowsu spremi `sandbox-key.pem` na sigurno mjesto. Zapamti ime `sandbox-key`.

---

## Korak 3 — konfiguracija Terraforma

U mapi `infra` kopiraj primjer i uredi ga:

```
cd infra
copy terraform.tfvars.example terraform.tfvars   (Windows)
```

Otvori `terraform.tfvars` i upiši:

```hcl
region           = "eu-central-1"
instance_type    = "m7i-flex.large"            # 8 GB RAM, dovoljno za model llama3.1 (8B)
key_name         = "sandbox-key"          # ime iz koraka 2
ssh_ingress_cidr = "TVOJA.JAVNA.IP.ADR/32" # vidi nize
```

Svoju javnu IP adresu doznaješ s https://checkip.amazonaws.com — na kraj dodaj `/32`
(npr. `93.140.10.5/32`). Time samo tvoje računalo može pristupiti instanci preko SSH-a.

---

## Korak 4 — podizanje instance

```
terraform init
terraform apply
```

Terraform ispiše što će stvoriti; upiši `yes`. Nakon minute ispiše izlaz, među
kojim je `instance_public_ip` i `ssh_command`. Zapiši IP adresu.

Instanca u pozadini sama instalira Docker i gVisor (skripta `user_data.sh`). To
traje 2–3 minute nakon što je instanca dostupna.

---

## Korak 5 — spajanje na instancu

```
ssh -i sandbox-key.pem ubuntu@<instance_public_ip>
```

Prvi put potvrdi otisak ključa s `yes`. Na Windowsu (PowerShell) koristi `ssh`
koji dolazi uz Windows 10/11. Ako javi grešku o dozvolama ključa, ispravi ih:
`icacls sandbox-key.pem /inheritance:r /grant:r "%USERNAME%:R"`. WSL nije potreban.

Provjeri da je postavljanje gotovo:

```
cat /var/log/sandbox/setup.done      # mora ispisati "postavljanje zavrseno"
docker --version
runsc --version                      # gVisor
ollama --version                     # lokalni model za agenta
```

Ako `setup.done` još ne postoji, pričekaj minutu — `user_data` još radi.

---

## Korak 6 — dohvat koda i priprema

Na instanci:

```
git clone https://github.com/<tvoje-ime>/zavrsni-sandbox.git projekt
cd projekt

# Python ovisnosti za orkestrator i ispitni okvir
pip install -r sandbox/requirements.txt

# Izgradi sliku izvrsnog okruzenja
docker build -f sandbox/Dockerfile.runner -t sandbox-runner:latest sandbox/

# Povuci lokalni model za agenta (za pokus S6). llama3.1 (8B) stane u m7i-flex.large.
ollama pull llama3.1
```

Kratka provjera da orkestrator radi (runc grana):

```
SBX_RUNTIME=runc uvicorn app.main:app --app-dir sandbox --port 8000 &
sleep 3
curl -s localhost:8000/execute -H 'content-type: application/json' \
     -d '{"code":"print(2+2)"}'
kill %1
```

Očekuješ odgovor s `"verdict":"ok"` i `"stdout":"4"`. Ako to radi, sve je spremno.

---

## Korak 7 — pokretanje cijelog vrednovanja

```
bash tests/run_all.sh
```

Skripta redom, za obje razine izolacije (runc pa gVisor):
  - pokrene orkestrator,
  - izvrši cijeli testni skup S1–S5 (`run_corpus.py`),
  - izmjeri performanse (`benchmark.py`),
  - ugasi orkestrator.

Na kraju ispiše sažete tablice. Sve datoteke rezultata su u `results/`:
  - `corpus-runc-hardened.jsonl`, `corpus-gvisor.jsonl` — ishodi napada
  - `benchmark-runc-hardened.json`, `benchmark-gvisor.json` — performanse

Za ponovni ispis tablica u bilo kojem trenutku:

```
python3 tests/report.py results/
```

### Pokus S6 — autonomni agent i posredno ubacivanje uputa

Ovaj pokus provlači zadatke kroz autonomnog agenta koji generira kod i izvršava
ga isključivo kroz sandbox. Agent poziva lokalni model preko Ollame, pa nema
troška ni API ključa. Sve radi jedna skripta, za obje razine izolacije:

```
bash tests/run_agent.sh
```

Skripta prvo snima kasetu (poziva model) na razini runc, zatim je reproducira na
gVisoru, čime su rezultati ponovljivi. Rezultati su u `results/injection-*.jsonl`
i popunjavaju Tablicu 4.4: koliko je puta agent nasjeo na ubačene upute i, od tih
slučajeva, koliko je puta izolacija zaustavila posljedicu.

Za jači model (bolja kvaliteta generiranog koda) uzmi veću instancu i model:

```
ollama pull llama3.1
AGENT_MODEL=llama3.1 bash tests/run_agent.sh
```

### Neobavezno: RedCode

```
git clone https://github.com/AI-secure/RedCode tests/redcode/RedCode
SBX_RUNTIME=runc uvicorn app.main:app --app-dir sandbox --port 8000 &
python3 tests/redcode_adapter.py --api http://127.0.0.1:8000 \
        --dataset tests/redcode/RedCode --limit 100
kill %1
```

---

## Korak 8 — prijenos rezultata i gašenje

Prekopiraj rezultate na svoje računalo (iz PowerShella, ne s instance):

```
scp -i sandbox-key.pem -r ubuntu@<instance_public_ip>:~/projekt/results ./results
```

Zatim OBAVEZNO ugasi svu infrastrukturu:

```
cd infra
terraform destroy
```

Upiši `yes`. Time se brišu instanca, sigurnosna skupina, IAM uloga i log grupa,
pa daljnjih troškova nema.

---

## Što s rezultatima

Brojke iz ispisa `report.py` (i iz `results/`) upisuju se u prazna mjesta `__` u
tablicama 4.1, 4.2 i 4.3 u Word dokumentu. Za graf vremena pokretanja (Slika 4.2)
podaci su u `benchmark-*.json`, polje `latency` → `startup_ms`.

## Ako nešto zapne

  - `docker: permission denied` → odjavi se i ponovno spoji na instancu (članstvo
    u docker grupi primjenjuje se tek nakon nove prijave), ili `newgrp docker`.
  - `runsc: command not found` pri gVisor dijelu → `user_data` još nije dovršio;
    provjeri `cat /var/log/sandbox/setup.done` i pričekaj.
  - orkestrator ne odgovara → pogledaj `results/api-*.log`.
