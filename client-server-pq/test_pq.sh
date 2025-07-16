#! /bin/bash

echo "[*] Avvio server PQ-RT..."
sudo gnome-terminal -- bash -c "./server_pq; exec bash" &
SERVER_PID=$!
sleep 4

sudo gnome-terminal -- bash -c "./client_pq 'CIAO 1'; exec bash" &
sudo gnome-terminal -- bash -c "./client_pq 'HELLO 2'; exec bash" &
sudo gnome-terminal -- bash -c "./client_pq 'TEST 3'; exec bash" &
sudo gnome-terminal -- bash -c "./client_pq 'OPENSSL 4'; exec bash" &
sudo gnome-terminal -- bash -c "./client_pq 'PQCRYPTO 5'; exec bash" &

sleep 10


echo "[*] Arresto server..."
sudo pkill server_pq
