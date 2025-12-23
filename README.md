# VM Service Project

A Flask web application for managing Proxmox VMs with user authentication.

## Features

- User registration and login
- Create predefined VMs (Bronze, Silver, Gold) in Proxmox containers
- View VM details including SSH access information

## Setup (sviluppo rapido)

Prerequisiti: Python 3.10+, accesso API Proxmox.

1. (Opzionale) Crea venv  
   `python -m venv .venv && .\.venv\Scripts\Activate.ps1`
2. Installa dipendenze  
   `pip install -r requirements.txt`
3. Esporta le variabili d’ambiente (PowerShell)  
   `.\scripts\set_env.ps1`  
   Variabili rilevanti:  
   - `PROXMOX_HOST` (es. 192.168.56.15)  
   - `PROXMOX_USER` + `PROXMOX_PASS` (password) **oppure** `PROXMOX_TOKEN_NAME` + `PROXMOX_TOKEN_VALUE` (token)  
   - `PROXMOX_NODE` (default `px1`)  
   - `PROXMOX_STORAGE` (default `local-lvm`)  
   - `DEFAULT_SSH_PASSWORD` (password root impostata sui container)  
4. Avvia l’app  
   `python app.py`

## Flusso d’uso
- Utente si registra, fa login, richiede una VM (bronze/silver/gold).
- Admin approva/rigetta la richiesta; in approvazione viene clonato il template LXC (vmid 2210/2220/2230 di default), avviato e configurato.
- Dashboard utente mostra credenziali SSH e IP (best-effort). Se l’IP non è immediatamente disponibile, c’è il pulsante “Ottieni IP” che prova a leggere l’indirizzo da dentro il container e ad avviare SSH.

## Note su rete/IP/SSH
- Assicurati che il template LXC abbia rete funzionante (DHCP o IP statico) e SSH abilitato; altrimenti l’app non potrà leggere l’IP né avviare SSH da remoto.  
- Se “Ottieni IP” non trova l’IP, verifica via console Proxmox con `ip -4 -o addr show dev eth0` e avvia SSH manualmente (`service ssh start` o `systemctl start ssh`) nel template di base e salvalo, così i cloni erediteranno la config.

## Deployment
- Pensata per girare in un container Proxmox con reachability verso l’API. Imposta le variabili via environment, non hardcodare credenziali.

## Security Notes
- Cambia subito password di default (`DEFAULT_SSH_PASSWORD` e admin web).  
- Usa token API al posto della password, quando possibile.  
- In produzione abilita hashing delle password applicative (non incluso in questo esempio didattico).***

## Fonti
- ChatGPT https://chatgpt.com/
- CopilotAI https://copilot.microsoft.com/
- StackOverFlow https://stackoverflow.com