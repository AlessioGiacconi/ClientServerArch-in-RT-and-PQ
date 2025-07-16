# Architettura Client Server Post-Quantum con Supporto Real-Time

🧠 ##Descrizione
Questo progetto implementa un sistema client-server sicuro basato su primitive Post-Quantum per lo scambio di chiavi (Key Encapsulation Mechanisms) e per la cifratura/autenticazione dei messaggi. Il sistema include anche una versione real-time multithreaded, con supporto per:

+ Scheduling a priorità reale (SCHED_FIFO)

+ Log di timestamp per misurazioni RTT

+ Gestione concorrente di più client

+ Segnalazione di errori e backtrace in caso di crash
