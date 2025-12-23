<# Quick env setup for Proxmox + app defaults.
   Usage (PowerShell):
     cd D:\Scuola\M340\VmServiceProject
     .\scripts\set_env.ps1

   Edit values below to match your environment before running.
#>

# === Proxmox connection ===
$env:PROXMOX_HOST = "192.168.56.15"    # Proxmox API host/IP
$env:PROXMOX_USER = "root@pam"         # user with realm (es. root@pam o user@pve)

# --- Token auth (alternativa; lasciato commentato) ---
#$env:PROXMOX_TOKEN_NAME  = "mytokenid" # solo il token id, senza l'utente
#$env:PROXMOX_TOKEN_VALUE = "tokensecret"
# Disattiva eventuali variabili token residue nella sessione:
Remove-Item Env:PROXMOX_TOKEN_NAME  -ErrorAction SilentlyContinue
Remove-Item Env:PROXMOX_TOKEN_VALUE -ErrorAction SilentlyContinue

# --- Password auth (default) ---
$env:PROXMOX_PASS = "Password&1"

# === VM defaults ===
$env:DEFAULT_SSH_PASSWORD = "Password&1" # password root impostata sulle VM
$env:PROXMOX_STORAGE      = "local-lvm"  # storage dove clonare
$env:PROXMOX_TIMEOUT      = "15"         # timeout richieste API (secondi)

Write-Host "Variabili ambiente impostate per questa sessione PowerShell."

