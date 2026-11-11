import os
from argon2 import PasswordHasher
from sqlalchemy import select
from backend.models import Base, engine, Session, Department, User

password=os.getenv('DEMO_PASSWORD','')
if len(password)<12: raise SystemExit('Задайте DEMO_PASSWORD не короче 12 символов')
Base.metadata.create_all(engine)
names=['IT-отдел','Технический отдел','Отдел закупок','Отдел продаж','Сервисный отдел','HR','Логистика и склад','Руководство']
with Session.begin() as db:
    for name in names:
        if not db.scalar(select(Department).where(Department.name==name)): db.add(Department(name=name))
    db.flush(); tech=db.scalar(select(Department).where(Department.name=='Технический отдел'))
    for login,role,department in [('employee','EMPLOYEE',None),('admin','SUPER_ADMIN',None),('manager','DEPARTMENT_MANAGER',tech.id),('executor','EXECUTOR',tech.id)]:
        if not db.scalar(select(User).where(User.login==login)): db.add(User(login=login,role=role,department_id=department,password_hash=PasswordHasher().hash(password)))
print('Демонстрационные отделы и пользователи созданы. Существующие пароли не изменены.')
