const app=document.querySelector('#app'); let me=null,csrf='',page='tickets',selected=null,notice='';
const labels={NEW:'Новое',ASSIGNED:'На рассмотрении',IN_PROGRESS:'В работе',NEEDS_INFO:'Ожидает уточнения',RESOLVED:'Реализовано',CLOSED:'Закрыто',REJECTED:'Отклонено',APPEAL:'Пересмотр отказа'};
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(path,opts={}){let r=await fetch('/api'+path,{credentials:'same-origin',...opts,headers:{'Content-Type':'application/json','X-CSRF-Token':csrf,...opts.headers}});let d=await r.json();if(!r.ok)throw Error(d.detail||'Ошибка запроса');return d}
function post(path,data){return api(path,{method:'POST',body:JSON.stringify(data)})}
function error(e){notice=`<div class="error">${esc(e.message)}</div>`;render()}
function login(){
 app.innerHTML=`<main class="login">
  <section class="login-brand" aria-labelledby="login-title">
   <div class="sidebar-brand"><span class="brand-mark" aria-hidden="true">М</span><span class="brand-title">MODUS FLOW</span></div>
   <h1 id="login-title">Обратная связь<br>и предложения сотрудников</h1>
   <p class="login-lead">Единый канал, чтобы сообщить о проблеме, предложить улучшение и видеть, что происходит с обращением дальше.</p>
   <ul class="login-points">
    <li><strong>Прозрачность</strong><span>Статус, ответственный и срок по обращению</span></li>
    <li><strong>Маршрутизация</strong><span>Назначение отдела по категории обращения</span></li>
    <li><strong>Результат</strong><span>Зафиксированные решения и аналитика обращений</span></li>
   </ul>
  </section>
  <div class="login-panel">
   <form class="login-card" id="login">
    <h2>Добро пожаловать</h2>
    <p>Введите логин и пароль.</p>
    <label>Логин<input name="login" required autocomplete="username"></label>
    <label>Пароль<input name="password" type="password" required autocomplete="current-password"></label>
    <button>Войти в систему</button>
    ${notice}
   </form>
  </div>
 </main>`;
 document.querySelector('#login').onsubmit=async e=>{e.preventDefault();try{me=await post('/login',Object.fromEntries(new FormData(e.target)));csrf=me.csrf;notice='';render()}catch(err){error(err)}}
}
function shell(content,title,sub){
 app.innerHTML=`<div class="shell">
  <aside class="sidebar">
   <div class="sidebar-brand"><span class="brand-mark" aria-hidden="true">М</span><div><div class="brand-title">MODUS FLOW</div><div class="brand-sub">Обратная связь</div></div></div>
   <nav class="nav" aria-label="Разделы">
    <button data-page="tickets">${me.role==='EXECUTOR'?'Мои задачи':me.role==='EMPLOYEE'?'Мои обращения':'Обращения'}</button>
    ${me.role==='EMPLOYEE'?'<button data-page="tasks">Мои задачи</button><button data-page="create">Новое обращение</button><button data-page="anonymous">Анонимный доступ</button>':''}
    ${me.role==='SUPER_ADMIN'?'<button data-page="analytics">Аналитика</button>':''}
   </nav>
   <div class="sidebar-footer">
    <div class="user-card"><span class="avatar" aria-hidden="true">${esc(me.login.slice(0,1).toUpperCase())}</span><span class="user-name">${esc(me.login)}</span></div>
    <button class="secondary" id="logout">Выйти</button>
   </div>
  </aside>
  <main class="main">
   <header class="topbar"><div><div class="eyebrow">${esc(sub||'Обзор')}</div><h1>${esc(title)}</h1></div>
    <div class="topbar-actions"><span class="badge">${esc(me.role)}</span>
    ${me.roles?.length>1?`<select id="working-role" aria-label="Рабочая роль">${me.roles.map((role,index)=>`<option value="${index}" ${role.role===me.role&&role.department_id===(me.department_id??null)?'selected':''}>${esc(role.role)}${role.department_id?' · отдел '+role.department_id:''}</option>`).join('')}</select>`:''}</div>
   </header>
   <div class="view">${notice}${content}</div>
  </main>
 </div>`;
 const rolePicker=document.querySelector('#working-role');
 if(rolePicker)rolePicker.onchange=async()=>{
  try { me=await post('/session/role',me.roles[Number(rolePicker.value)]); csrf=me.csrf; page='tickets'; selected=null; notice=''; render(); }
  catch(err){error(err);}
 };
 document.querySelectorAll('[data-page]').forEach(b=>b.onclick=()=>{page=b.dataset.page;selected=null;notice='';render()});document.querySelector('#logout').onclick=async()=>{await post('/logout',{});me=null;csrf='';notice='';render()}
}
async function render(){
 if(!me)return login();
 try{
  if(selected)return await detail();
  if(page==='create')return await create();
  if(page==='anonymous')return anonymous();
  if(page==='analytics')return await analytics();
  return await tickets();
 }catch(err){
  shell(`<p class="error">${esc(err.message)}</p>`,'Обращения');
 }
}

async function tickets(){
 const queue=page==='tasks'||me.role==='EXECUTOR'?'assigned':me.role==='EMPLOYEE'?'own':'';
 const rows=await api('/tickets'+(queue?'?queue='+queue:''));
 const title=queue==='assigned'?'Мои задачи':queue==='own'?'Мои обращения':'Обращения';
 shell(`${queue==='own'?'<div class="hero"><h2>Идеи и вопросы в одном месте</h2><button id="new">Создать обращение ＋</button></div>':''}
  <div class="panel"><h2>${title} <small>${rows.length}</small></h2></div>
  <div class="ticket-list">${rows.map(t=>`<button class="ticket" data-id="${t.id}"><div><small class="ticket-code">${esc(t.number)} · ${esc(t.category)}</small><strong>${esc(t.title)}</strong></div><span class="badge status-${esc(t.status)}">${esc(labels[t.status])}</span></button>`).join('')||'<p class="empty">Пока обращений нет.</p>'}</div>`,title);
 document.querySelector('#new')?.addEventListener('click',()=>{page='create';render()});
 document.querySelectorAll('[data-id]').forEach(button=>button.onclick=()=>{selected=button.dataset.id;render()});
}

async function create(){
 const categories=await api('/categories');
 shell(`<div class="panel narrow"><h2>Расскажите, что можно улучшить</h2>
  <form id="create">
   <label>Тип обращения<select name="kind"><option value="REQUEST">Обращение или предложение</option><option value="FEEDBACK">Положительный отзыв</option></select></label>
   <label>Заголовок<input name="title" required minlength="3" maxlength="200"></label>
   <label>Описание<textarea name="description" required minlength="5" maxlength="5000"></textarea></label>
   <label>Категория<select name="category" required><option value="">Выберите категорию</option>${categories.filter(c=>c.active).map(c=>`<option>${esc(c.name)}</option>`).join('')}</select></label>
   <label>Предлагаемое решение<textarea name="solution" maxlength="2000"></textarea></label>
   <label class="check"><input type="checkbox" name="anonymous">Отправить анонимно</label>
   <p>При анонимной отправке сохраните секретный код. Он показывается один раз.</p>
   <button>Отправить обращение</button>
  </form></div>`,'Новое обращение');
 document.querySelector('#create').onsubmit=async e=>{
  e.preventDefault();
  const fields=new FormData(e.currentTarget);
  try{
   const data=await post('/tickets',{...Object.fromEntries(fields),anonymous:fields.has('anonymous')});
   notice=data.anonymous_token?`<div class="success">Обращение создано. Секретный код: <strong>${esc(data.anonymous_token)}</strong></div>`:'<div class="success">Обращение создано.</div>';
   page=data.anonymous_token?'anonymous':'tickets';render();
  }catch(err){error(err);}
 };
}

const actionNames={accept:'Принять на рассмотрение',redirect:'Перенаправить',assign:'Назначение и срок',return:'Вернуть на рассмотрение',clarify:'Запросить уточнение',answer:'Ответить на уточнение',submit_result:'Передать результат',confirm:'Подтвердить результат',close:'Закрыть обращение',refuse:'Оформить отказ',feedback:'Обработать отзыв',appeal:'Запросить пересмотр отказа',admit:'Решить вопрос допуска',claim:'Участвовать в пересмотре',vote:'Зафиксировать позицию'};
const reasonLabels={redirect:'Причина перенаправления',return:'Причина возврата',clarify:'Вопрос',answer:'Ответ автора',submit_result:'Результат',refuse:'Причина отказа',feedback:'Как обработан отзыв',appeal:'Обоснование запроса',admit:'Обоснование допуска',vote:'Обоснование позиции'};
function forms(ticket,departments=[],workers=[]){
 return (ticket.actions||[]).map(action=>`<details class="panel"><summary>${actionNames[action]}</summary>
  <form class="workflow-form" data-action="${action}">
   ${action==='redirect'?`<label>Новый отдел<select name="department_id" required>${departments.filter(d=>d.active&&d.id!==ticket.department_id).map(d=>`<option value="${d.id}">${esc(d.name)}</option>`).join('')}</select></label>`:''}
   ${action==='assign'?`<label>Исполнитель<select name="executor_id" required>${workers.filter(w=>w.eligible_worker).map(w=>`<option value="${w.id}" ${ticket.executor_id===w.id?'selected':''}>${esc(w.login)}</option>`).join('')}</select></label>
    <label>Срок<input type="datetime-local" name="due_at" required></label>`:''}
   ${action==='submit_result'||action==='appeal'?`<label>${action==='appeal'?'С чем вы не согласны':'Описание работы'}<textarea name="description" required maxlength="5000"></textarea></label>`:''}
   ${action==='admit'?'<label>Допуск<select name="decision"><option value="ALLOW">Допустить</option><option value="DENY">Отказать</option></select></label>':''}
   ${action==='vote'?'<label>Позиция<select name="decision"><option value="REOPEN">Возобновить рассмотрение</option><option value="UPHOLD">Подтвердить отказ</option></select></label>':''}
   ${reasonLabels[action]?`<label>${reasonLabels[action]}<textarea name="reason" required maxlength="5000"></textarea></label>`:''}
   <button>Сохранить действие</button>
  </form></details>`).join('');
}

function card(ticket,departments=[],workers=[]){
 return `<section class="panel"><small>${esc(ticket.number)} · ${esc(ticket.category)}</small>
  <h2>${esc(ticket.title)}</h2><span class="badge status-${esc(ticket.status)}">${esc(labels[ticket.status])}</span>
  <p>${esc(ticket.description||'Организационный обзор обращения')}</p>
  ${ticket.result?`<p><b>Результат:</b> ${esc(ticket.result)}</p>`:''}
 </section>
 ${forms(ticket,departments,workers)}
 ${ticket.clarifications?.map(item=>`<section class="panel"><h3>Уточнение</h3><p>${esc(item.question)}</p><p>${esc(item.answer||'Ожидается ответ')}</p></section>`).join('')||''}
 ${ticket.work_results?.map(item=>`<section class="panel"><h3>Результат работы</h3><p>${esc(item.description)}</p><p>${esc(item.outcome)}</p></section>`).join('')||''}
 ${ticket.refusals?.map(item=>`<section class="panel"><h3>Отказ № ${item.id}</h3><p>${esc(item.reason)}</p>${item.appeals.map(appeal=>`<p>${esc(appeal.motivation)}</p>`).join('')}</section>`).join('')||''}
 ${ticket.history?.length?`<section class="panel"><h2>История обработки</h2>${ticket.history.map(entry=>`<div class="history"><b>${esc(entry.event)}</b><p>${esc(entry.reason)}</p><small>${esc(entry.created_at)}</small></div>`).join('')}</section>`:''}`;
}

function bindActions(root,ticket,save){
 root.querySelectorAll('[data-action]').forEach(form=>form.onsubmit=async event=>{
  event.preventDefault();
  const values=Object.fromEntries(new FormData(form));
  for(const field of ['department_id','executor_id'])if(values[field])values[field]=Number(values[field]);
  if(values.due_at)values.due_at=new Date(values.due_at).toISOString();
  try { await save({...values,action:form.dataset.action,record_version:ticket.record_version}); }
  catch(err){error(err);}
 });
}

function anonymous(){
 shell('<section class="panel narrow"><h2>Открыть анонимное обращение</h2><form id="anon"><label>Секретный код<input name="token" type="password" required autocomplete="off"></label><button>Найти</button></form></section><div id="result"></div>','Анонимный доступ');
 const view=document.querySelector('#result');
 document.querySelector('#anon').onsubmit=async e=>{
  e.preventDefault();
  const token=new FormData(e.currentTarget).get('token');
  const show=ticket=>{view.innerHTML=card(ticket);bindActions(view,ticket,async data=>show(await post('/anonymous/actions',{...data,token})));};
  try{show(await post('/anonymous',{token}));}catch(err){error(err);}
 };
}

async function detail(){
 const id=selected;
 const [ticket,departments]=await Promise.all([api('/tickets/'+id),api('/departments')]);
 const workers=ticket.actions?.includes('assign')?await api('/users'):[];
 const integration=ticket.access==='internal'?`<section class="panel"><h2>1С:УТ</h2>
  <form id="search"><label>Поиск товара<input name="q" value="сканер"></label><button class="secondary">Получить данные из 1С</button></form><div id="products"></div>
  <form id="order"><label>Заявка на закупку<input name="item" value="Сканер штрихкодов Zebra DS2208" required></label><button class="secondary">Создать заявку</button></form>
  <h3>Обмен с 1С</h3>${ticket.integration.map(event=>`<p>${esc(event.operation)} · ${event.ok?'успешно':'ошибка'}</p><pre>${esc(event.result)}</pre>`).join('')}
 </section>`:'';
 shell(`<button class="plain" id="back">← Все обращения</button><div class="detail"><div>${card(ticket,departments,workers)}</div><div>${integration}</div></div>`,'Карточка обращения',ticket.number);
 document.querySelector('#back').onclick=()=>{selected=null;render()};
 bindActions(app,ticket,async data=>{
  await post('/tickets/'+id+'/actions',data);
  if(data.action==='redirect')selected=null;
  notice='<div class="success">Действие сохранено</div>';render();
 });
 document.querySelector('#search')?.addEventListener('submit',async e=>{
  e.preventDefault();
  try{
   const products=await api('/tickets/'+id+'/products?q='+encodeURIComponent(new FormData(e.currentTarget).get('q')));
   document.querySelector('#products').innerHTML=`<pre>${esc(JSON.stringify(products,null,2))}</pre>`;
  }catch(err){error(err);}
 });
 document.querySelector('#order')?.addEventListener('submit',async e=>{
  e.preventDefault();
  try{
   const order=await post('/tickets/'+id+'/orders',{item:new FormData(e.currentTarget).get('item'),key:crypto.randomUUID()});
   notice=`<div class="success">Заявка создана ${esc(order.number)}</div>`;render();
  }catch(err){error(err);}
 });
}
async function analytics(){let a=await api('/analytics');shell(`<div class="grid">${[['Всего',a.total],['Новые',a.new],['В работе',a.in_progress],['Решены',a.resolved],['Успешные запросы 1С',a.integration_success],['Ошибки 1С',a.integration_errors]].map(([n,v])=>`<div class="panel"><div class="muted">${n}</div><div class="metric">${v}</div></div>`).join('')}</div><p>Показатели рассчитаны по сохранённым обращениям и событиям обмена.</p>`,'Аналитика','Показатели')}
api('/me').then(x=>{me=x;csrf=x.csrf;render()}).catch(()=>render());
