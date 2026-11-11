import os
from argon2 import PasswordHasher
from sqlalchemy import select
from backend.models import Base, engine, Session, Department, User, Category, RoutingRule, Role, IntegrationSetting
from backend.routing import RULES

password=os.getenv('DEMO_PASSWORD','')
if len(password)<12: raise SystemExit('Задайте DEMO_PASSWORD не короче 12 символов')
from sqlalchemy import inspect
if not inspect(engine).has_table('alembic_version'):
    raise SystemExit('Сначала выполните: python -m alembic upgrade head (для старой базы см. README)')
names=['IT-отдел','Технический отдел','Отдел закупок','Отдел продаж','Сервисный отдел','HR','Логистика и склад','Руководство']
with Session.begin() as db:
    for name in ['EMPLOYEE','SUPER_ADMIN','DEPARTMENT_MANAGER','EXECUTOR']:
        if not db.scalar(select(Role).where(Role.name==name)): db.add(Role(name=name))
    if not db.scalar(select(IntegrationSetting).where(IntegrationSetting.name=='configuration_source')): db.add(IntegrationSetting(name='configuration_source',value='environment'))
    for name in names:
        if not db.scalar(select(Department).where(Department.name==name)): db.add(Department(name=name))
    db.flush(); tech=db.scalar(select(Department).where(Department.name=='Технический отдел'))
    for name in ['Оборудование','IT','Закупки','Продажи','Сервис','Персонал','Логистика','Другое']:
        if not db.scalar(select(Category).where(Category.name==name)): db.add(Category(name=name))
    for keyword,name in RULES:
        dept=db.scalar(select(Department).where(Department.name==name))
        if dept and not db.scalar(select(RoutingRule).where(RoutingRule.keyword==keyword)): db.add(RoutingRule(keyword=keyword,department_id=dept.id))
    for login,role,department in [('employee','EMPLOYEE',None),('admin','SUPER_ADMIN',None),('manager','DEPARTMENT_MANAGER',tech.id),('executor','EXECUTOR',tech.id)]:
        if not db.scalar(select(User).where(User.login==login)): db.add(User(login=login,role=role,department_id=department,password_hash=PasswordHasher().hash(password)))
print('Демонстрационные отделы и пользователи созданы. Существующие пароли не изменены.')
