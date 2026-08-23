# Kasete (snimljeni odgovori modela)

Kaseta je JSON datoteka s odgovorima jezicnog modela, snimljenima jednom kako bi
pokusi bili u cijelosti ponovljivi bez ponovnog pozivanja modela.

## Snimanje kasete (jednom, treba API kljuc)

```bash
export AGENT_API_KEY=sk-...            # OpenAI ili uskladeno sucelje
export AGENT_LLM_MODE=record
python3 -m agent.run_injection --api http://127.0.0.1:8000 \
        --cassette agent/cassettes/injection.json
```

Time se `injection.json` popuni odgovorima modela za svaki slucaj S6.

## Reprodukcija (zadano, bez API kljuca)

```bash
export AGENT_LLM_MODE=replay           # zadano
python3 -m agent.run_injection --api http://127.0.0.1:8000 \
        --cassette agent/cassettes/injection.json
```

U ovom nacinu agent ne poziva model, nego cita odgovore iz kasete. Rezultati su
svaki put jednaki, sto je nuzno za ponovljivost mjerenja u radu.

Snimljena kaseta ukljucuje se u repozitorij kao dio rezultata, pa se cijeli pokus
S6 moze ponoviti bez pristupa modelu.
