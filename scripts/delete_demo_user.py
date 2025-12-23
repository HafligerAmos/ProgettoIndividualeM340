# Script: delete_demo_user.py
# Deletes user demo@demo.ch and related VM and VMRequest records from the app DB
# Run inside the project's venv: .\venv\Scripts\Activate.ps1 && python scripts\delete_demo_user.py

from app import app, db, User, VM, VMRequest

with app.app_context():
    user = User.query.filter_by(email='demo@demo.ch').first()
    if not user:
        print('User demo@demo.ch not found. No changes.')
    else:
        print(f'Found user: id={user.id} username={user.username} email={user.email}')
        vms = VM.query.filter_by(user_id=user.id).all()
        reqs = VMRequest.query.filter_by(user_id=user.id).all()
        print(f' - {len(vms)} VM(s) associated')
        for vm in vms:
            print(f'   deleting VM id={vm.id} vmid={vm.vmid} name={vm.name} ip={vm.ip}')
            db.session.delete(vm)
        print(f' - {len(reqs)} request(s) associated')
        for r in reqs:
            print(f'   deleting request id={r.id} type={r.vm_type} status={r.status}')
            db.session.delete(r)
        print('Deleting user account...')
        db.session.delete(user)
        db.session.commit()
        print('Deletion complete.')
