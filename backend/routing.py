RULES = [('сканер','Технический отдел'),('оборуд','Технический отдел'),('компьют','IT-отдел'),('программ','IT-отдел'),('закуп','Отдел закупок'),('склад','Логистика и склад'),('продаж','Отдел продаж'),('сотрудник','HR')]
def recommend(title, description, category):
    text = f'{title} {description} {category}'.lower()
    for keyword, department in RULES:
        if keyword in text: return department, f'Совпадение по ключу «{keyword}»'
    return 'Руководство', 'Нет совпадения с локальными правилами; требуется ручная проверка'
