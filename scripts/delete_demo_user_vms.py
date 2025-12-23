# Deletes VM records for user demo@demo.ch from the app DB
# Run inside project's venv:
# .\venv\Scripts\Activate.ps1
# python scripts\delete_demo_user_vms.py

from app import app, db, VM, User

with app.app_context():
    user = User.query.filter_by(email='demo@demo.ch').first()
    if not user:
        print('User demo@demo.ch not found. No VMs deleted.')
    else:
        vms = VM.query.filter_by(user_id=user.id).all()
        if not vms:
            print(f'No VM records found for user demo@demo.ch (user id={user.id}).')
        else:
            print(f'Found {len(vms)} VM record(s) for demo@demo.ch (user id={user.id}). Deleting...')
            for vm in vms:
                print(f' - deleting id={vm.id} vmid={vm.vmid} name={vm.name} ip={vm.ip}')
                db.session.delete(vm)
            db.session.commit()
            print('Deletion complete.')
