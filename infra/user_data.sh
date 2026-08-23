#!/usr/bin/env bash
# Postavljanje instance: Docker, gVisor (runsc) i priprema okruzenja.
# Pokrece se jednom pri prvom pokretanju instance.
set -euxo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl gnupg git python3-pip

# --- Docker ---
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
  > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io

# --- gVisor (runsc) ---
(
  set -e
  ARCH=$(uname -m)
  URL="https://storage.googleapis.com/gvisor/releases/release/latest/${ARCH}"
  curl -fsSL "${URL}/runsc" -o /usr/local/bin/runsc
  curl -fsSL "${URL}/containerd-shim-runsc-v1" -o /usr/local/bin/containerd-shim-runsc-v1
  chmod 0755 /usr/local/bin/runsc /usr/local/bin/containerd-shim-runsc-v1
)

# Registracija oba runtimea u Dockeru.
cat > /etc/docker/daemon.json <<'JSON'
{
  "runtimes": {
    "runsc": {
      "path": "/usr/local/bin/runsc"
    }
  }
}
JSON
systemctl enable docker
systemctl restart docker

# Korisnik ubuntu mora moci pokretati docker bez sudo.
usermod -aG docker ubuntu

# --- swap ---
# Sigurnosna mreza za slucaj vrsnog opterecenja memorije pri ucitavanju modela.
# Na m7i.large (8 GB) nije nuzan, ali ne smeta; na manjoj instanci je koristan.
if [ ! -f /swapfile ]; then
  fallocate -l 4G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=4096
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
  echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

# --- Ollama (lokalni jezicni model za agenta, bez API kljuca) ---
# Instalira se kao servis na 127.0.0.1:11434. Model se povlaci u koraku
# postavljanja projekta (vidi DEPLOY.md), a ne ovdje, da boot ostane brz.
curl -fsSL https://ollama.com/install.sh | sh || true
systemctl enable ollama || true
systemctl start ollama || true

# --- direktorij za revizijski zapis ---
mkdir -p /var/log/sandbox
chown ubuntu:ubuntu /var/log/sandbox

# --- dohvat koda projekta ---
# Zamijeniti URL vlastitim repozitorijem ili kopirati kod preko scp.
# git clone https://example.com/vlad/zavrsni-sandbox.git /opt/sandbox || true

echo "postavljanje zavrseno" > /var/log/sandbox/setup.done
