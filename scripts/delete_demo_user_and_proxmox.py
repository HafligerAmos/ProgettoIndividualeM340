#!/usr/bin/env python3
"""
Delete user demo@demo.ch, their VM records and (optionally) Proxmox containers.
Run inside the project's venv:
  .\venv\Scripts\Activate.ps1
  python scripts\delete_demo_user_and_proxmox.py

The script will detect the sqlite DB `site.db`, discover table names, list VMs and ask for confirmation.
"""
import os
import sqlite3
import sys
from getpass import getpass

project_root = os.path.dirname(os.path.dirname(__file__))
DB_PATH = os.path.join(project_root, 'site.db')
if not os.path.exists(DB_PATH):
    # fallback to instance/site.db if app uses instance folder
    alt = os.path.join(project_root, 'instance', 'site.db')
    if os.path.exists(alt):
        DB_PATH = alt

def find_table_with_column(conn, column_name):
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [r[0] for r in cur.fetchall()]
    for t in tables:
        try:
            cur.execute(f"PRAGMA table_info('{t}')")
            cols = [r[1] for r in cur.fetchall()]
            if column_name in cols:
                return t
        except Exception:
            continue
    return None

def main():
    if not os.path.exists(DB_PATH):
        print('DB not found at', DB_PATH)
        sys.exit(1)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    user_table = find_table_with_column(conn, 'email') or 'user'
    vm_table = find_table_with_column(conn, 'vmid') or find_table_with_column(conn, 'name') or 'vm'
    req_table = find_table_with_column(conn, 'vm_type') or 'vmrequest'

    cur = conn.cursor()
    cur.execute(f"SELECT * FROM {user_table} WHERE email=?", ('demo@demo.ch',))
    user = cur.fetchone()
    if not user:
        print('User demo@demo.ch not found in DB.')
        return

    user_id = user['id']
    uname = user['username'] if 'username' in user.keys() else None
    print(f"Found user demo@demo.ch id={user_id} username={uname}")

    # list VMs
    vms = []
    try:
        cur.execute(f"SELECT id, vmid, name, ip FROM {vm_table} WHERE user_id=?", (user_id,))
        vms = cur.fetchall()
    except Exception:
        # fallback: try selecting rows with user_id column present
        try:
            cur.execute("SELECT id, vmid, name, ip FROM vm WHERE user_id=?", (user_id,))
            vms = cur.fetchall()
        except Exception:
            vms = []

    print(f'Found {len(vms)} VM record(s) for demo@demo.ch:')
    for r in vms:
        print(' -', dict(r))

    # list requests
    try:
        cur.execute(f"SELECT id, vm_type, status FROM {req_table} WHERE user_id=?", (user_id,))
        reqs = cur.fetchall()
    except Exception:
        reqs = []
    print(f'Found {len(reqs)} request(s) for demo@demo.ch')

    confirm = input('Type YES to delete the user and their DB records (this cannot be undone): ')
    if confirm.strip() != 'YES':
        print('Aborted by user.')
        return

    # Optionally delete Proxmox containers if vmids present and env vars exist
    vmids = [r['vmid'] for r in vms if r['vmid']]
    if vmids:
        prox_host = os.getenv('PROXMOX_HOST')
        prox_user = os.getenv('PROXMOX_USER')
        prox_pass = os.getenv('PROXMOX_PASS')
        if prox_host and prox_user and prox_pass:
            do_proxmox = input('PROXMOX credentials found in env — delete corresponding containers on Proxmox as well? Type YES to proceed: ')
            if do_proxmox.strip() == 'YES':
                try:
                    from proxmoxer import ProxmoxAPI
                    prox = ProxmoxAPI(prox_host, user=prox_user, password=prox_pass, verify_ssl=False)
                    for vid in vmids:
                        try:
                            print('Attempting to delete container vmid=', vid)
                            prox.nodes('px1').lxc(vid).delete()
                            print('Delete request sent for', vid)
                        except Exception as e:
                            print('Failed to delete', vid, 'error:', e)
                except Exception as e:
                    print('Could not connect to Proxmox API:', e)
        else:
            print('Proxmox credentials not found in environment; skipping Proxmox deletion.')

    # Delete VM records
    try:
        cur.execute(f"DELETE FROM {vm_table} WHERE user_id=?", (user_id,))
    except Exception:
        try:
            cur.execute("DELETE FROM vm WHERE user_id=?", (user_id,))
        except Exception:
            pass

    # Delete requests
    try:
        cur.execute(f"DELETE FROM {req_table} WHERE user_id=?", (user_id,))
    except Exception:
        pass

    # Delete user
    cur.execute(f"DELETE FROM {user_table} WHERE id=?", (user_id,))
    conn.commit()
    print('Deleted user, VM records and requests from DB.')

if __name__ == '__main__':
    main()
