# Script: delete_all_vms_db.py
# Deletes all VM records from the local SQLite DB used by app.py
# Run inside the project's venv: .\venv\Scripts\Activate.ps1 && python scripts\delete_all_vms_db.py

from app import app, db, VM

with app.app_context():
    vms = VM.query.all()
    if not vms:
        print('No VM records found in DB.')
    else:
        print(f'Found {len(vms)} VM records. Listing vmids and names:')
        for vm in vms:
            print(f' - id={vm.id} vmid={vm.vmid} name={vm.name} ip={vm.ip}')
        confirm = input('Type YES to delete all VM records from DB: ')
        if confirm.strip() == 'YES':
            for vm in vms:
                db.session.delete(vm)
            db.session.commit()
            print('All VM records deleted from DB.')
        else:
            print('Aborted. No changes made.')
