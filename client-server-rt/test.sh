#!/bin/bash

echo "[*] Avvio server..."
sudo gnome-terminal -- bash -c "./server_rt; exec bash" &
SERVER_PID=$!
sleep 4

sudo gnome-terminal -- bash -c "./client_rt 'CIAO 1'; exec bash" &
sudo gnome-terminal -- bash -c "./client_rt 'SALVE 2'; exec bash" &
sudo gnome-terminal -- bash -c "./client_rt 'BUONGIORNO 3'; exec bash" &
sudo gnome-terminal -- bash -c "./client_rt 'BUONANOTTE 4'; exec bash" &
sudo gnome-terminal -- bash -c "./client_rt 'AU REVOIR 5'; exec bash" &

sleep 10

echo "[*] Arresto server.."
sudo pkill server_rt