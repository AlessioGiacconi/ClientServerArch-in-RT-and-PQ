# Architettura Client Server Post-Quantum con Supporto Real-Time

## 🧠 Progetto
Questo progetto implementa un sistema client-server sicuro basato su primitive Post-Quantum per lo scambio di chiavi (Key Encapsulation Mechanisms) e per la cifratura/autenticazione dei messaggi. Il sistema include anche una versione real-time multithreaded, con supporto per:

+ **Scheduling a priorità reale (SCHED_FIFO)**

+ **Log di timestamp per misurazioni RTT**

+ **Gestione concorrente di più client**

+ **Segnalazione di errori e backtrace in caso di crash**

## 🔐 Obiettivo
Questa implementazione non è altro che un punto di partenza in quanto la struttura qua sviluppata sarà ampliata, in modo da replicare un client onion-like, con entry, guard ed exit node. L'obiettivo sarà, quindi, quello di valutare le performance delle primitive post-quantum integrate in un contesto real-time e multiclient, confrontandole con soluzioni legacy attualmente in uso.

## 🔐 Tecnologie e Primitive Utilizzate

+ **OpenSSL 3.x + OQS Provider**
  - Scambio chiavi: `mlkem512` (basato su Kyber512)
  - Cifratura simmetrica: `ChaCha20-Poly1305` (AEAD)
+ **RSA + AES-256-CBC** (versione legacy per confronto)
+ **C (POSIX/Linux) con `pthread`, `sched`, `signals`**

## 📁 Componenti
🔹 `server_pq.c` / `client_pq.c`
Comunicazioni Post-Quantum in tempo reale con:
+ Key exchange via `mlkem512`
+ Messaggi cifrati con ChaCha20-Poly1305
+ Supporto `SCHED_FIFO`, multithreading, logging

🔹 `server_rt.c` / `client_rt.c`
Versione legacy basata su:
+ Key exchange via RSA
+ Cifratura con AES-256-CBC
+ Supporto `SCHED_FIFO`, multithreading, calcolo RTT, logging

🔹 `test.sh` 
Script bash che:
+ Avvia `server_rt` in un terminale separato
+ Lancia 5 client con messaggi diversi in parallelo
+ Arresta automaticamente il server dopo 10 secondi

🔹 `test_pq.sh`
Contropartita di `test.sh` per la versione Post-Quantum:
+ Avvia `server_pq`
+ Lancia multipli `client_pq`
+ Arresta automaticamente il server dopo 10 secondi

## ⚙️ Requisiti
+ Linux con `gnome-terminal`
+ Compilatore `gcc`
+ OpenSSL 3.0+ compilato con supporto provider esterni
+ `liboqs` + `oqs-provider` installati e configurati

### ⚠️ Ambiente OpenSSL
```c
setenv("OPENSSL_CONF", "/percorso/openssl.cnf", 1);
setenv("OPENSSL_MODULES", "/usr/lib/x86_64-linux-gnu/ossl-modules", 1);
```
Oppure da terminale:
```bash
export OPENSSL_CONF=~/openssl-pq/openssl.cnf
export OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules
```

## 🚀 Compilazione

```bash
gcc -Wall -o server_pq server_pq.c -lssl -lcrypto -lpthread -lrt
gcc -Wall -o client_pq client_pq.c -lssl -lcrypto -lpthread -lrt

gcc -Wall -Wno-deprecated-declarations -o server_rt server_rt.c -lssl -lcrypto -lrt
gcc -Wall -Wno-deprecated-declarations -o client_rt client_rt.c -lssl -lcrypto
```

## 🧪 Esecuzione

### Esecuzione manuale

```bash
sudo ./server_pq
sudo ./client_pq "Ciao da PQ client"
```

### Esecuzione batch
```
chmod +x test.sh
./test.sh
chmod +x test_pq.sh
./test_pq.sh
```
