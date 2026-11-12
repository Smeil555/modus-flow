import React,{useEffect,useState,useRef} from 'react';
import {createRoot} from 'react-dom/client';
import axios from 'axios';
import {QueryClient,QueryClientProvider,useQuery,useQueryClient} from '@tanstack/react-query';
import {BrowserRouter} from 'react-router-dom';
import {BarChart,Bar,XAxis,YAxis,Tooltip,ResponsiveContainer} from 'recharts';
import {Bell, ChartNoAxesColumn, ClipboardList, Database, FilePlus2, GitBranch, LockKeyhole, Network, Settings2, UsersRound, Workflow} from 'lucide-react';
import {
 CaseActions, CaseRecords, Offices, RouteVersions, AppealQueue, leaders, administrators, statuses,
 type Department as Dept, type Category, type Candidate, type WorkflowCase, type Office,
 type CategoryRoute, type RoutingIssue, type AppealQueueEntry,
} from './workflow';
import './style.css';
const navIcons:Record<string,typeof ClipboardList>={
 tickets:ClipboardList,create:FilePlus2,anonymous:LockKeyhole,analytics:ChartNoAxesColumn,
 departments:Network,settings:GitBranch,users:UsersRound,system:Settings2,audit:ClipboardList,
 data:Database,integration:Workflow,notifications:Bell,tasks:ClipboardList,outgoing:GitBranch,offices:Network,appeals:ClipboardList,issues:Bell,
};
const accountRoles=['EMPLOYEE',...leaders,'EXECUTOR',...administrators,'SUPER_ADMIN'];
const roleNames:Record<string,string>={ADMIN:'Администратор',ADMIN_ASSISTANT:'Ассистент администратора',DEPARTMENT_DEPUTY:'Заместитель начальника отдела'};
const roleLabel=(role:string)=>roleNames[role]?`${roleNames[role]} (${role})`:role;
type RoleGrant={role:string;department_id:number|null};
type User={login:string;role:string;csrf:string;permissions?:string[];department_id?:number|null;roles?:RoleGrant[]};
type Ticket=WorkflowCase & {id:number;number:string;title:string;description:string;category:string;solution:string;anonymous:boolean;recommendation:string;reason:string;status:string;result:string;implemented:boolean;department_id:number|null;executor_id:number|null;due_at:string|null;history?:{event:string;created_at:string;reason?:string|null}[];comments?:{id:number;author:string;body:string}[];integration?:{operation:string;result:string;ok:boolean}[];external?:{id:number;number:string;status:string;mode:string}[];attachments?:{id:number;name:string;size:number}[]};
type Person={id:number;login:string;role:string;department_id:number|null;active:boolean;roles?:RoleGrant[]};
type Note={id:number;ticket_id:number|null;message:string;read:boolean};
const http=axios.create({baseURL:'/api',withCredentials:true}); let csrf='';
http.interceptors.request.use(c=>{if(csrf)c.headers['X-CSRF-Token']=csrf;return c});
http.interceptors.response.use(r=>r,e=>{if(e.response?.status===401&&!['/login','/me'].includes(e.config?.url))window.dispatchEvent(new Event('session-expired'));return Promise.reject(e)});
const get=async<T,>(p:string):Promise<T>=>(await http.get<T>(p)).data;
const post=async<T,>(p:string,d:unknown):Promise<T>=>(await http.post<T>(p,d)).data;
function errorText(e:unknown){if(!axios.isAxiosError(e))return e instanceof Error?e.message:'Ошибка';const detail=e.response?.data?.detail;return typeof detail==='string'?detail:Array.isArray(detail)?'Проверьте поля формы':'Ошибка соединения';}
export function App(){
 const [user,setUser]=useState<User|null>(null),[ready,setReady]=useState(false),[page,setPage]=useState('tickets'),[id,setId]=useState<number|null>(null),[message,setMessage]=useState(''),[dark,setDark]=useState(false),[secret,setSecret]=useState(''); const qc=useQueryClient();
 useEffect(()=>{get<User>('/me').then(u=>{csrf=u.csrf;setUser(u)}).catch(()=>{}).finally(()=>setReady(true))},[]);
 useEffect(()=>{const expired=()=>{csrf='';setSecret('');setId(null);setPage('tickets');setUser(null);qc.clear();setMessage('Сессия истекла. Войдите снова.')};window.addEventListener('session-expired',expired);return()=>window.removeEventListener('session-expired',expired)},[qc]);
 useEffect(()=>{document.documentElement.dataset.theme=dark?'dark':'light'},[dark]);
 const run:Run=async(fn,success='Готово')=>{
  try { await fn(); if(success!==null)setMessage(success); await qc.invalidateQueries(); return true; }
  catch(e){ setMessage(errorText(e)); return false; }
 };
 if(!ready)return <div className="center">Загрузка…</div>;
 if(!user)return (
  <main className="login">
   <section className="login-brand" aria-labelledby="login-title">
    <div className="sidebar-brand"><span className="brand-mark" aria-hidden="true">М</span><span className="brand-title">MODUS FLOW</span></div>
    <h1 id="login-title">Обратная связь<br/>и предложения сотрудников</h1>
    <p className="login-lead">Единый канал, чтобы сообщить о проблеме, предложить улучшение и видеть, что происходит с обращением дальше.</p>
    <ul className="login-points">
     <li><strong>Прозрачность</strong><span>Статус, ответственный и срок по обращению</span></li>
     <li><strong>Маршрутизация</strong><span>Назначение отдела по категории обращения</span></li>
     <li><strong>Результат</strong><span>Зафиксированные решения и аналитика обращений</span></li>
    </ul>
   </section>
   <div className="login-panel">
    <form className="login-card" onSubmit={e=>{e.preventDefault();const f=new FormData(e.currentTarget);run(async()=>{const u=await post<User>('/login',{login:f.get('login'),password:f.get('password')});csrf=u.csrf;setUser(u)},'')}}>
     <h2>Добро пожаловать</h2>
     <p>Введите логин и пароль.</p>
     <label>Логин<input name="login" required autoComplete="username"/></label>
     <label>Пароль<input name="password" type="password" required autoComplete="current-password"/></label>
     <button>Войти</button>
     {message&&<div className="notice" role="status">{message}</div>}
    </form>
   </div>
  </main>
 );
 const can=(permission:string)=>user.role==='SUPER_ADMIN'||user.permissions?.includes(permission);
 const companyAdmin=administrators.includes(user.role);
 const leader=leaders.includes(user.role);
 const primaryTitle=user.role==='EMPLOYEE'?'Мои обращения':user.role==='EXECUTOR'?'Мои задачи':
   leader?'Очередь отдела':companyAdmin?'Контроль обращений':'Обращения';
 const titles:Record<string,string>={
  tickets:primaryTitle,create:'Новое обращение',anonymous:'Анонимный доступ',tasks:'Мои задачи',
  outgoing:'Обращения сотрудников отдела',analytics:'Аналитика',departments:'Отделы',users:'Управление пользователями',
  system:'Системные настройки',audit:'Журнал действий',data:'Состояние базы',integration:'Интеграция 1С',
  settings:'Категории и маршруты',offices:'Отделы и роли',appeals:'Пересмотры отказов',issues:'Ошибки маршрутизации',
  notifications:'Уведомления',profile:'Профиль',
 };
 const sections=['tickets',...(user.role==='EMPLOYEE'?['create','anonymous','tasks']:[]),
  ...(leader?['outgoing']:[]),...(companyAdmin?['offices','appeals']:[]),
  ...(can('analytics.read')?['analytics']:[]),...(can('departments.manage')?['departments']:[]),
  ...(companyAdmin||can('categories.manage')?['settings']:[]),
  ...(companyAdmin||user.role==='SUPER_ADMIN'?['issues']:[]),
  ...(user.role==='SUPER_ADMIN'?['users','system']:[]),...(can('audit.read')?['audit']:[]),
  ...(can('data.read')?['data']:[]),...(can('integration.read')?['integration']:[]),'notifications'];
 const queue=page==='tasks'||user.role==='EXECUTOR'?'assigned':page==='outgoing'?'outgoing':
  leader?'incoming':user.role==='EMPLOYEE'?'own':undefined;
 const navigate=(p:string)=>{setPage(p);setId(null);setMessage('');if(p!=='anonymous')setSecret('')};
 return (
  <div className="shell">
   <aside className="sidebar">
    <div className="sidebar-brand">
     <span className="brand-mark" aria-hidden="true">М</span>
     <div><div className="brand-title">MODUS FLOW</div><div className="brand-sub">Обратная связь</div></div>
    </div>
    <nav className="nav" aria-label="Разделы">
     {sections.map(p=>{
      const l=titles[p];
      const Icon=navIcons[p];
      return <button className={page===p?'active':''} key={p} onClick={()=>navigate(p)} aria-current={page===p?'page':undefined}><Icon aria-hidden="true"/>{l}</button>;
     })}
    </nav>
    <div className="sidebar-footer">
     <button className="user-card" onClick={()=>navigate('profile')}><span className="avatar" aria-hidden="true">{user.login.slice(0,1).toUpperCase()}</span><span className="user-name">Профиль · {user.login}</span></button>
     <button className="secondary" onClick={()=>run(async()=>{await post('/logout',{});csrf='';setSecret('');setPage('tickets');setId(null);setUser(null);qc.clear()},'')}>Выйти</button>
    </div>
   </aside>
   <main className="main">
    <header className="topbar">
     <h1>{id?'Карточка обращения':titles[page]}</h1>
     <div className="topbar-actions">
      <span className="badge">{roleLabel(user.role)}</span>
      {(user.roles?.length||0)>1&&<select aria-label="Рабочая роль" value={JSON.stringify({role:user.role,department_id:user.department_id??null})} onChange={e=>{const role=JSON.parse(e.target.value);run(async()=>{const next=await post<User>("/session/role",role);setSecret("");setId(null);setPage("tickets");qc.clear();setUser(next)},"Роль переключена")}}>{user.roles?.map(r=><option key={JSON.stringify(r)} value={JSON.stringify(r)}>{roleLabel(r.role)}{r.department_id?" · отдел "+r.department_id:""}</option>)}</select>}
      <button className="secondary" onClick={()=>setDark(!dark)} aria-label="Сменить тему">{dark?'☀':'☾'}</button>
     </div>
    </header>
    <div className="view">
     {message&&<div className="notice" role="status">{message}</div>}
     {id?<Details key={id} id={id} user={user} run={run} back={()=>setId(null)}/>
      :['tickets','tasks','outgoing'].includes(page)?<Tickets key={page} open={setId} create={()=>navigate('create')} title={titles[page]} queue={queue}/>
      :page==='create'?<Create run={run} done={(token,notice)=>{navigate(token?'anonymous':'tickets');setSecret(token||'');setMessage(notice)}}/>
      :page==='anonymous'?<Anonymous initial={secret} run={run}/>
      :page==='analytics'?<Analytics/>:page==='departments'?<Departments run={run}/>
      :page==='users'?<Users run={run}/>:page==='profile'?<AccountSecurity run={run}/>
      :page==='system'?<SystemSettings run={run}/>:page==='audit'?<AdminAudit/>
      :page==='data'?<DataStatus/>:page==='integration'?<IntegrationMonitor/>
      :page==='settings'?<Settings run={run} companyAdmin={companyAdmin} systemAdmin={user.role==='SUPER_ADMIN'}/>
      :page==='offices'?<DepartmentOffices run={run}/>:page==='appeals'?<Appeals open={setId}/>
      :page==='issues'?<RoutingIssues/>:<Notifications run={run} open={setId}/>}

    </div>
   </main>
  </div>
 );
}
type Run=(fn:()=>Promise<unknown>,success?:string|null)=>Promise<boolean>;
function AccountSecurity({run}:{run:Run}){
 const [saving,setSaving]=useState(false);
 return <section className="panel account-security">
  <h2>Настройки аккаунта</h2><h3>Безопасность</h3>
  <form onSubmit={e=>{
   e.preventDefault();
   const form=e.currentTarget, fields=new FormData(form);
   setSaving(true);
   void run(async()=>{
    await post('/password',{
     current_password:fields.get('current_password'),
     password:fields.get('password'),
     confirmation:fields.get('confirmation'),
    });
    form.reset();
   },'Пароль изменён').finally(()=>setSaving(false));
  }}>
   <h4>Изменить пароль</h4>
   <label>Текущий пароль<input name="current_password" type="password" required maxLength={200} autoComplete="current-password"/></label>
   <label>Новый пароль<input name="password" type="password" required minLength={12} maxLength={200} autoComplete="new-password"/></label>
   <label>Подтверждение нового пароля<input name="confirmation" type="password" required minLength={12} maxLength={200} autoComplete="new-password"/></label>
   <button disabled={saving}>Сохранить новый пароль</button>
  </form>
 </section>;
}

function Tickets({open,create,title,queue}:{open:(id:number)=>void;create:()=>void;title:string;queue?:string}){
 const [filter,setFilter]=useState('');
 const [params,setParams]=useState('');
 const {data=[],isLoading,error}=useQuery({queryKey:['tickets',queue,params],queryFn:()=>{
  const query=new URLSearchParams(params);
  if(queue)query.set('queue',queue);
  return get<Ticket[]>('/tickets'+(query.size?'?'+query:''));
 }});
 const {data:ds=[]}=useQuery({queryKey:['departments'],queryFn:()=>get<Dept[]>('/departments')});
 const {data:cats=[]}=useQuery({queryKey:['categories'],queryFn:()=>get<Category[]>('/categories')});
 const rows=data.filter(t=>(t.title+' '+t.number).toLowerCase().includes(filter.toLowerCase()));
 return <>
  {queue==='own'&&<section className="hero"><div><h2>Идеи и вопросы в одном месте</h2><p>Отслеживайте рассмотрение и ответы по своим обращениям.</p></div><button onClick={create}>Создать обращение +</button></section>}
  <section className="panel">
   <div className="row spread"><h2>{title} <small>{data.length}</small></h2><input aria-label="Фильтр" placeholder="Поиск по названию или номеру" value={filter} onChange={e=>setFilter(e.target.value)}/></div>
   <form className="filters" onSubmit={e=>{
    e.preventDefault();
    const query=new URLSearchParams();
    for(const [key,value] of new FormData(e.currentTarget)) if(value){
     const dateSuffix=key==='from_date'?'T00:00:00':key==='to_date'?'T23:59:59':'';
     query.set(key,String(value)+dateSuffix);
    }
    setParams(query.toString());
   }}>
    <label>Статус<select name="status"><option value="">Все</option>{Object.entries(statuses).map(([k,v])=><option key={k} value={k}>{v}</option>)}</select></label>
    <label>Категория<select name="category"><option value="">Все</option>{cats.map(c=><option key={c.id}>{c.name}</option>)}</select></label>
    <label>Отдел<select name="department_id"><option value="">Все</option>{ds.map(d=><option key={d.id} value={d.id}>{d.name}</option>)}</select></label>
    <label>Приоритет<select name="priority"><option value="">Все</option>{['LOW','NORMAL','HIGH','URGENT'].map(x=><option key={x}>{x}</option>)}</select></label>
    <label>Дата с<input name="from_date" type="date"/></label>
    <label>Дата по<input name="to_date" type="date"/></label>
    {['incoming','assigned'].includes(queue||'')&&<label>Обмен с 1С<select name="integration"><option value="">Все</option><option value="true">Есть события</option><option value="false">Нет событий</option></select></label>}
    <button>Применить</button>
   </form>
  </section>
  <div className="ticket-list">
   {error?<p role="alert">{errorText(error)}</p>:isLoading?<p>Загрузка…</p>:rows.map(t=>
    <button className="ticket" key={t.id} onClick={()=>open(t.id)}>
     <div><small className="ticket-code">{t.number} · {t.category}</small><strong>{t.title}</strong><small>{t.anonymous?'Анонимно':'Именное'} · {ds.find(d=>d.id===t.department_id)?.name||'Отдел не назначен'}</small></div>
     <span className={'badge status-'+t.status}>{statuses[t.status]||t.status}</span>
    </button>)}
   {!error&&!isLoading&&!rows.length&&<p className="empty">Нет обращений по выбранным условиям.</p>}
  </div>
 </>;
}

async function fileContent(file: File){
 if(file.size>5*1024*1024)throw Error('Файл больше 5 МБ');
 return new Promise<string>((resolve,reject)=>{
  const reader=new FileReader();
  reader.onload=()=>resolve(String(reader.result).split(',')[1]);
  reader.onerror=()=>reject(Error('Не удалось прочитать файл'));
  reader.readAsDataURL(file);
 });
}

function Create({run,done}:{run:Run;done:(token:string|null,message:string)=>void}){
 const [similar,setSimilar]=useState<{number:string;title:string}[]>([]);
 const [anonymous,setAnonymous]=useState(false);
 const [busy,setBusy]=useState(false);
 const {data:categories=[]}=useQuery({queryKey:['categories'],queryFn:()=>get<Category[]>('/categories')});
 const {data:ds=[]}=useQuery({queryKey:['departments'],queryFn:()=>get<Dept[]>('/departments')});
 return <section className="panel narrow">
  <h2>Расскажите, что можно улучшить</h2>
  <form onSubmit={e=>{
   e.preventDefault();
   const f=new FormData(e.currentTarget), file=f.get('file') as File|null;
   setBusy(true);
   void run(async()=>{
    const content=file?.size?await fileContent(file):null;
    const {ticket,anonymous_token:token}=await post<{ticket:Ticket;anonymous_token:string|null}>('/tickets',{
     title:f.get('title'),description:f.get('description'),category:f.get('category'),kind:f.get('kind'),
     solution:f.get('solution'),priority:f.get('priority'),
     preferred_department_id:f.get('department')?Number(f.get('department')):null,anonymous,
    });
    let notice=token?'Сохраните код: он показан только сейчас.':'Обращение создано';
    if(content&&file){
     try{
      if(token)await post('/anonymous/attachments',{token,content_base64:content});
      else await post('/tickets/'+ticket.id+'/attachments',{name:file.name,content_base64:content});
     }catch(err){notice+=' Вложение можно загрузить из карточки. '+errorText(err);}
    }
    done(token,notice);
   },null).finally(()=>setBusy(false));
  }}>
   <label>Тип обращения<select name="kind"><option value="REQUEST">Обращение или предложение</option><option value="FEEDBACK">Положительный отзыв</option></select></label>
   <label>Заголовок<input name="title" minLength={3} maxLength={200} required/></label>
   <label>Описание<textarea name="description" minLength={5} maxLength={5000} required/></label>
   <label>Категория<select name="category" required defaultValue=""><option value="" disabled>Выберите категорию</option>
    {categories.filter(c=>c.active).map(c=><option key={c.id}>{c.name}</option>)}
   </select></label>
   <label>Предполагаемый отдел<select name="department"><option value="">Не указан</option>{ds.filter(d=>d.active).map(d=><option key={d.id} value={d.id}>{d.name}</option>)}</select></label>
   <label>Приоритет<select name="priority" defaultValue="NORMAL"><option value="NORMAL">Обычный</option><option value="LOW">Низкий</option><option value="HIGH">Высокий</option><option value="URGENT">Срочный</option></select></label>
   <label>Предлагаемое решение<textarea name="solution" maxLength={2000}/></label>
   <label className="check"><input type="checkbox" name="anonymous" checked={anonymous} onChange={e=>setAnonymous(e.target.checked)}/>Отправить анонимно</label>
   <label>Вложение<input key={String(anonymous)} name="file" type="file" accept={anonymous?'image/png,image/jpeg':'.png,.jpg,.jpeg,.pdf,.txt'}/></label>
   {anonymous&&<p>Для анонимных обращений доступны PNG и JPEG. Не указывайте личные данные в тексте и на изображении.</p>}
   <div className="row"><button disabled={busy}>Отправить</button>
    <button type="button" className="secondary" disabled={busy} onClick={e=>{
     const f=new FormData(e.currentTarget.form!);
     void run(async()=>setSimilar(await post('/similar',{title:f.get('title'),description:f.get('description'),category:f.get('category'),solution:'',anonymous})),'Поиск завершён');
    }}>Похожие обращения</button></div>
   {similar.map(x=><p key={x.number}>{x.number} · {x.title}</p>)}
  </form>
 </section>;
}

function Anonymous({initial,run}:{initial:string;run:Run}){
 const [token,setToken]=useState(initial);
 const [openedToken,setOpenedToken]=useState('');
 const [ticket,setTicket]=useState<Ticket>();
 const [body,setBody]=useState('');
 return <>
  <section className="panel narrow">
   <p>Сохраните код в надёжном месте. После отправки он показывается один раз.</p>
   {initial&&<div className="notice"><b>Ваш код:</b> <code>{initial}</code></div>}
   <form onSubmit={e=>{e.preventDefault();void run(async()=>{const next=await post<Ticket>('/anonymous',{token});setTicket(next);setOpenedToken(token);},'Обращение найдено');}}>
    <label>Секретный код<input type="password" value={token} onChange={e=>{setToken(e.target.value);setTicket(undefined);}} autoComplete="off" required/></label>
    <button>Открыть</button>
   </form>
  </section>
  {ticket&&<>
   <section className="panel">
    <small>{ticket.number} · {ticket.category}</small><h2>{ticket.title}</h2>
    <span className={'badge status-'+ticket.status}>{statuses[ticket.status]}</span>
    <p>{ticket.description}</p>{ticket.result&&<p><b>Результат:</b> {ticket.result}</p>}
    {ticket.status==='NEW'&&<EditTicket ticket={ticket} run={run} path="/anonymous/edit" token={openedToken} setTicket={setTicket}/>}
   </section>
   <CaseActions ticket={ticket} save={data=>run(async()=>setTicket(await post<Ticket>('/anonymous/actions',{...data,token:openedToken})),'Действие сохранено')}/>
   <CaseRecords ticket={ticket}/>
   <section className="panel">
    <AnonymousAttachments token={openedToken} ticket={ticket} setTicket={setTicket} run={run}/>
    <h3>Комментарии</h3>
    {ticket.comments?.map(c=><p key={c.id}><b>{c.author}:</b> {c.body}</p>)}
    <label>Комментарий<textarea value={body} onChange={e=>setBody(e.target.value)} maxLength={3000}/></label>
    <button disabled={!body.trim()} onClick={()=>run(async()=>{
     setTicket(await post<Ticket>('/anonymous/comment',{token:openedToken,body}));setBody('');
    },'Комментарий отправлен')}>Отправить комментарий</button>
   </section>
   <TicketHistory ticket={ticket}/>
  </>}
 </>;
}
function EditTicket({ticket,run,path,token,setTicket}:{ticket:Ticket;run:Run;path:string;token?:string;setTicket?:(t:Ticket)=>void}){return <details><summary>Редактировать обращение</summary><form onSubmit={e=>{e.preventDefault();let f=new FormData(e.currentTarget);run(async()=>{const updated=await post<Ticket>(path,{title:f.get('title'),description:f.get('description'),solution:f.get('solution'),...(token?{token}:{})});setTicket?.(updated)},'Обращение обновлено')}}><label>Заголовок<input name="title" defaultValue={ticket.title} minLength={3} required/></label><label>Описание<textarea name="description" defaultValue={ticket.description} minLength={5} required/></label><label>Предлагаемое решение<textarea name="solution" defaultValue={ticket.solution}/></label><button className="secondary">Сохранить изменения</button></form></details>}

function AnonymousAttachments({token,ticket,setTicket,run}:{token:string;ticket:Ticket;setTicket:(t:Ticket)=>void;run:Run}){return <div><h3>Анонимные изображения</h3><p>PNG или JPEG до 5 МБ. Имя файла и метаданные удаляются. Проверьте само изображение: лица, надписи или другие детали могут раскрыть автора.</p>{ticket.attachments?.map(a=><p key={a.id}><button className="secondary" onClick={()=>run(async()=>{const r=await fetch('/api/anonymous/attachments/download',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify({token,attachment_id:a.id})});if(!r.ok)throw Error('Не удалось скачать изображение');const url=URL.createObjectURL(await r.blob());const link=document.createElement('a');link.href=url;link.download=a.name;link.click();URL.revokeObjectURL(url)},'Изображение скачано')}>{a.name}</button></p>)}<form onSubmit={e=>{e.preventDefault();const form=e.currentTarget,file=(form.elements.namedItem('image') as HTMLInputElement).files?.[0];if(!file)return;run(async()=>{if(file.size>5*1024*1024)throw Error('Файл больше 5 МБ');const image=await new Promise<string>((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>resolve(String(reader.result).split(',')[1]);reader.onerror=()=>reject(Error('Не удалось прочитать файл'));reader.readAsDataURL(file)});await post('/anonymous/attachments',{token,content_base64:image});setTicket(await post<Ticket>('/anonymous',{token}));form.reset()},'Изображение добавлено')}}><label>Изображение<input name="image" type="file" accept="image/png,image/jpeg" required/></label><button className="secondary">Добавить изображение</button></form></div>}
function TicketHistory({ticket}:{ticket:Ticket}){
 if(!ticket.history?.length)return null;
 return <section className="panel"><h2>История обработки</h2>{ticket.history.map((entry,index)=>
  <div className="history" key={index}><b>{entry.event}</b>{entry.reason&&<p>{entry.reason}</p>}<small>{entry.created_at}</small></div>
 )}</section>;
}

function Details({id,user,run,back}:{id:number;user:User;run:Run;back:()=>void}){
 const {data:t,isLoading,error}=useQuery({queryKey:['ticket',id],queryFn:()=>get<Ticket>('/tickets/'+id),retry:false});
 const {data:ds=[]}=useQuery({queryKey:['departments'],queryFn:()=>get<Dept[]>('/departments')});
 const {data:workers=[]}=useQuery({queryKey:['workers',user.department_id],queryFn:()=>get<Candidate[]>('/users'),enabled:t?.actions?.includes('assign')});
 const [products,setProducts]=useState<unknown>(null);
 const orderKey=useRef(crypto.randomUUID());
 if(error)return <><button className="secondary" onClick={back}>← К списку</button><p role="alert">{errorText(error)}</p></>;
 if(isLoading||!t)return <p>Загрузка…</p>;
 return <>
  <button className="secondary" onClick={back}>← К списку</button>
  <div className="detail">
   <div>
    <section className="panel">
     <small>{t.number} · {t.category}</small><h2>{t.title}</h2>
     <span className={'badge status-'+t.status}>{statuses[t.status]||t.status}</span>
     {t.access==='oversight'?<p>Организационный обзор обращения.</p>:<p>{t.description}</p>}
     <p><b>Отдел:</b> {ds.find(d=>d.id===t.department_id)?.name||'Не назначен'}</p>
     {t.owner_id&&<p><b>Ответственный:</b> {t.owner_id}</p>}
     {t.access!=='oversight'&&<><p><b>Предложение:</b> {t.solution||'Не указано'}</p><p><b>Результат:</b> {t.result||'Пока не указан'}</p></>}
     <p><b>Срок:</b> {t.due_at?new Date(t.due_at+'Z').toLocaleString():'Не задан'}</p>
     {t.can_edit&&<EditTicket ticket={t} run={run} path={'/tickets/'+id+'/edit'}/>}
     {t.can_mark_implemented&&<button className="secondary" onClick={()=>run(
      ()=>post('/tickets/'+id+'/implementation',{implemented:!t.implemented}),'Отметка сохранена'
     )}>{t.implemented?'Снять отметку реализации':'Отметить предложение реализованным'}</button>}
    </section>
    <CaseRecords ticket={t}/>
    {(t.can_comment||!!t.comments?.length)&&<section className="panel">
     <h2>Комментарии</h2>
     {t.comments?.map(c=><p key={c.id}><b>{c.author}:</b> {c.body}</p>)}
     {t.can_comment&&<form onSubmit={e=>{
      e.preventDefault();
      const form=e.currentTarget, fields=new FormData(form);
      void run(async()=>{await post('/tickets/'+id+'/comments',{body:fields.get('body')});form.reset();},'Комментарий добавлен');
     }}><label>Комментарий<textarea name="body" required maxLength={3000}/></label><button>Отправить</button></form>}
    </section>}
    <TicketHistory ticket={t}/>
    {t.integration&&<section className="panel"><h2>История обмена</h2>
     {t.integration.map((x,i)=><div key={i}><p>{x.operation} · {x.ok?'успешно':'ошибка'}</p><pre>{x.result}</pre></div>)}
     {!t.integration.length&&<p>Запросов пока нет.</p>}
    </section>}
   </div>
   <div>
    <CaseActions ticket={t} departments={ds} workers={workers} save={data=>run(async()=>{
     await post('/tickets/'+id+'/actions',data);
     if(data.action==='redirect')back();
    },'Действие сохранено')}/>
    {(t.can_attach||!!t.attachments?.length)&&<section className="panel"><h2>Вложения</h2>
     {t.attachments?.map(a=><p key={a.id}><a href={'/api/tickets/'+id+'/attachments/'+a.id}>{a.name}</a> · {Math.ceil(a.size/1024)} КБ</p>)}
     {t.can_attach&&<form onSubmit={e=>{
      e.preventDefault();const form=e.currentTarget,file=(form.elements.namedItem('file') as HTMLInputElement).files?.[0];
      if(file)void run(async()=>{await post('/tickets/'+id+'/attachments',{name:file.name,content_base64:await fileContent(file)});form.reset();},'Файл добавлен');
     }}><label>Файл<input name="file" type="file" accept=".png,.jpg,.jpeg,.pdf,.txt" required/></label><button className="secondary">Загрузить</button></form>}
    </section>}
    {t.access==='internal'&&<section className="panel"><h2>1С:УТ</h2><p>Режим и сервис задаются настройками. MOCK использует тестовые данные.</p>
     <form onSubmit={e=>{
      e.preventDefault();const f=new FormData(e.currentTarget);
      void run(async()=>setProducts(await get('/tickets/'+id+'/products?q='+encodeURIComponent(String(f.get('q'))))),'Данные получены');
     }}><label>Поиск товара<input name="q" defaultValue="сканер"/></label><button className="secondary">Получить данные из 1С</button></form>
     {products!==null&&<pre>{JSON.stringify(products,null,2)}</pre>}
     <form onSubmit={e=>{
      e.preventDefault();const f=new FormData(e.currentTarget);
      void run(async()=>{await post('/tickets/'+id+'/orders',{item:f.get('item'),key:orderKey.current});orderKey.current=crypto.randomUUID();},'Заявка создана');
     }}><label>Заявка на закупку<input name="item" defaultValue="Сканер штрихкодов Zebra DS2208" required/></label><button className="secondary">Создать заявку</button></form>
     {t.external?.map(x=><div key={x.id}><p>{x.number} · {x.status} · {x.mode}</p>
      <button className="secondary" onClick={()=>run(()=>post('/tickets/'+id+'/orders/'+x.id+'/refresh',{}),'Статус обновлён')}>Обновить статус</button></div>)}
    </section>}
   </div>
  </div>
 </>;
}
function Analytics(){const {data:a}=useQuery({queryKey:['analytics'],queryFn:()=>get<Record<string,any>>('/analytics')});if(!a)return <p>Загрузка…</p>;return <><div className="metrics">{[['Всего',a.total],['Новые',a.new],['В работе',a.in_progress],['Решены',a.resolved],['Реализованные предложения',a.implemented_suggestions],['Просрочены',a.overdue],['Завершено, %',a.completion_rate],['Первый ответ, ч',a.first_response_hours??'—'],['Решение, ч',a.resolution_hours??'—'],['Успешные запросы 1С',a.integration_success],['Ошибки 1С',a.integration_errors]].map(([n,v])=><div className="panel" key={n}><small>{n}</small><div className="metric">{v}</div></div>)}</div><p>Среднее время первого ответа рассчитывается по первому комментарию сотрудника обработки; время решения — по первому переходу в «Решено».</p><section className="panel"><h2>Обращения по отделам</h2><div style={{height:300}}><ResponsiveContainer><BarChart data={Object.entries(a.departments).map(([name,value])=>({name,value}))}><XAxis dataKey="name" hide/><YAxis allowDecimals={false} tick={{fill:'var(--muted)'}}/><Tooltip contentStyle={{background:'var(--surface)',borderColor:'var(--border)',borderRadius:10}} itemStyle={{color:'var(--text)'}} cursor={{fill:'var(--surface-soft)'}}/><Bar dataKey="value" fill="var(--brand)" radius={[7,7,3,3]}/></BarChart></ResponsiveContainer></div>{Object.entries(a.departments).map(([name,value])=><p key={name}>{name}: {String(value)}</p>)}<h2>Категории</h2>{Object.entries(a.categories).map(([name,value])=><p key={name}>{name}: {String(value)}</p>)}<h2>Повторяющиеся заголовки</h2>{Object.keys(a.repeated_titles).length?Object.entries(a.repeated_titles).map(([name,value])=><p key={name}>{name}: {String(value)}</p>):<p>Совпадений пока нет.</p>}</section></>}
function IntegrationMonitor(){const {data:events=[]}=useQuery({queryKey:['integration-events'],queryFn:()=>get<{id:number;ticket_id:number;operation:string;ok:boolean;created_at:string}[]>('/integration/events')});const {data:health,isError}=useQuery({queryKey:['integration-health'],queryFn:()=>get<{mode:string}>('/integration/health'),retry:false});return <section className="panel"><h2>Монитор интеграции 1С</h2><p>{isError?'Сервис недоступен':`Сервис доступен · режим ${health?.mode||'...'}`}</p>{events.map(e=><div className="history" key={e.id}><b>REQ-{String(e.ticket_id).padStart(6,'0')} · {e.operation}</b><small>{e.ok?'Успешно':'Ошибка'} · {e.created_at}</small></div>)}{!events.length&&<p>Событий обмена пока нет.</p>}</section>}
function Departments({run}:{run:Run}){const {data=[]}=useQuery({queryKey:['departments'],queryFn:()=>get<Dept[]>('/departments')});return <section className="panel"><h2>Добавить отдел</h2><form onSubmit={e=>{e.preventDefault();let form=e.currentTarget,f=new FormData(form);run(async()=>{await post('/departments',{name:f.get('name'),description:f.get('description'),active:true});form.reset()},'Отдел создан')}}><label>Название<input name="name" required/></label><label>Описание<input name="description"/></label><button>Добавить</button></form><h2>Справочник</h2>{data.map(d=><form className="record" key={d.id} onSubmit={e=>{e.preventDefault();let f=new FormData(e.currentTarget);run(()=>post('/departments/'+d.id,{name:f.get('name'),description:f.get('description'),active:f.has('active')}),'Отдел обновлён')}}><input name="name" defaultValue={d.name} required/><input name="description" defaultValue={d.description}/><label className="check"><input type="checkbox" name="active" defaultChecked={d.active}/>Активен</label><button className="secondary">Сохранить</button></form>)}</section>}
type AccountDialog={kind:'create'}|{kind:'edit'|'password'|'permissions';account:Person};

function Users({run}:{run:Run}){
 const {data=[],error,isPending}=useQuery({queryKey:['users'],queryFn:()=>get<Person[]>('/users')});
 const {data:ds=[]}=useQuery({queryKey:['departments'],queryFn:()=>get<Dept[]>('/departments')});
 const [search,setSearch]=useState(''),[role,setRole]=useState(''),[dept,setDept]=useState('');
 const [dialog,setDialog]=useState<AccountDialog|null>(null);
 const rows=data.filter(u=>u.login.toLowerCase().includes(search.trim().toLowerCase())&&(!role||u.role===role)&&(!dept||String(u.department_id)===dept));
 return <section className="panel">
 <div className="row spread"><p>Аккаунты · {rows.length} из {data.length}</p><button onClick={()=>setDialog({kind:'create'})}>Создать аккаунт</button></div>
 <div className="filters"><label>Поиск по логину<input value={search} onChange={e=>setSearch(e.target.value)}/></label>
 <label>Роль<select value={role} onChange={e=>setRole(e.target.value)}><option value="">Все роли</option>{accountRoles.map(r=><option key={r} value={r}>{roleLabel(r)}</option>)}</select></label>
 <label>Отдел<select value={dept} onChange={e=>setDept(e.target.value)}><option value="">Все отделы</option><option value="null">Без отдела</option>{ds.map(d=><option key={d.id} value={d.id}>{d.name}</option>)}</select></label></div>
 {error?<p role="alert">{errorText(error)}</p>:isPending?<p>Загрузка…</p>:<div className="account-table"><table><thead><tr><th>Логин</th><th>Роль</th><th>Отдел</th><th>Состояние</th><th>Действия</th></tr></thead><tbody>
 {rows.map(account=><tr key={account.id}><td><b>{account.login}</b></td><td>{roleLabel(account.role)}</td><td>{ds.find(d=>d.id===account.department_id)?.name||'—'}</td><td><span className={`badge status-${account.active?'active':'inactive'}`}>{account.active?'Активен':'Заблокирован'}</span></td>
 <td><div className="row account-actions"><button className="secondary" onClick={()=>setDialog({kind:'edit',account})}>Изменить</button><button className="secondary" onClick={()=>setDialog({kind:'permissions',account})}>Разрешения</button><button className="secondary" onClick={()=>setDialog({kind:'password',account})}>Сбросить пароль</button></div></td></tr>)}
 </tbody></table>{!rows.length&&<p>Аккаунты не найдены.</p>}</div>}
 {dialog&&<AccountEditor dialog={dialog} departments={ds} close={()=>setDialog(null)} run={run}/>}</section>;
}

function AccountEditor({dialog,departments,close,run}:{dialog:AccountDialog;departments:Dept[];close:()=>void;run:Run}){
 const account=dialog.kind==='create'?null:dialog.account;
 const ref=useRef<HTMLDialogElement>(null);
 useEffect(()=>{ref.current?.showModal()},[]);
 const [busy,setBusy]=useState(false),[error,setError]=useState('');
 const path=account?'/users/'+account.id:'/users';
 const save=async(url:string,body:unknown)=>{
   setBusy(true);setError('');
   try{await post(url,body);close();await run(async()=>{},'Изменения сохранены')}
   catch(e){setError(errorText(e))}
   finally{setBusy(false)}
 };
 const title={create:'Создать аккаунт',edit:'Изменить аккаунт',password:'Сбросить пароль',permissions:'Разрешения'}[dialog.kind];
 return <dialog ref={ref} className="panel account-dialog" onCancel={close} aria-labelledby="account-dialog-title">
 <div className="row spread"><h2 id="account-dialog-title">{title}{account?' · '+account.login:''}</h2><button type="button" className="secondary" onClick={close}>Закрыть</button></div>
 {error&&<p role="alert" className="notice">{error}</p>}
 {dialog.kind==='permissions'?<><PermissionForm account={dialog.account} busy={busy} save={permissions=>save(path+'/permissions',{permissions})}/><h3>Дополнительные роли</h3><RoleGrants user={dialog.account} departments={departments} run={run}/></>:
 <form onSubmit={e=>{
   e.preventDefault();const f=new FormData(e.currentTarget);
   if(dialog.kind==='password'){void save(path+'/password',{password:f.get('password')});return}
   const fields={login:f.get('login'),role:f.get('role'),department_id:f.get('department_id')?Number(f.get('department_id')):null};
   void save(path,account?{...fields,active:f.has('active')}:{...fields,password:f.get('password')});
 }}>
 {dialog.kind!=='password'&&<><label>Логин<input name="login" defaultValue={account?.login} minLength={3} maxLength={100} required/></label>
 <label>Роль<select name="role" defaultValue={account?.role}>{accountRoles.map(r=><option key={r} value={r}>{roleLabel(r)}</option>)}</select></label>
 <label>Отдел<select name="department_id" defaultValue={account?.department_id??''}><option value="">Без отдела</option>{departments.filter(d=>d.active||d.id===account?.department_id).map(d=><option key={d.id} value={d.id}>{d.name}</option>)}</select></label></>}
 {dialog.kind==='edit'?<label className="check"><input name="active" type="checkbox" defaultChecked={account?.active}/>Аккаунт активен</label>:<label>Пароль<input name="password" type="password" required minLength={12} maxLength={200} autoComplete="new-password"/></label>}
 <button disabled={busy}>{dialog.kind==='create'?'Создать аккаунт':'Сохранить'}</button></form>}</dialog>;
}

function PermissionForm({account,busy,save}:{account:Person;busy:boolean;save:(permissions:string[])=>void}){
 const {data,error}=useQuery({queryKey:['permissions',account.id],queryFn:()=>get<{catalog:Record<string,string>;permissions:string[]}>('/users/'+account.id+'/permissions')});
 if(error)return <p role="alert">{errorText(error)}</p>;
 if(!data)return <p>Загрузка…</p>;
 return <form onSubmit={e=>{e.preventDefault();save(new FormData(e.currentTarget).getAll('permission').map(String))}}>
 {account.role==='SUPER_ADMIN'&&<p>Роль SUPER_ADMIN уже включает все разрешения.</p>}
 {Object.entries(data.catalog).map(([key,label])=><label className="check" key={key}><input name="permission" type="checkbox" value={key} defaultChecked={data.permissions.includes(key)}/>{label}</label>)}
 <button disabled={busy}>Сохранить разрешения</button></form>;
}

function AdminAudit(){
 const {data,error}=useQuery({queryKey:['admin-audit'],queryFn:()=>get<{id:number;actor:string;action:string;created_at:string}[]>('/admin/audit')});
 return <section className="panel">{error?<p role="alert">{errorText(error)}</p>:!data?<p>Загрузка…</p>:!data.length?<p>Действий пока нет.</p>:data.map(entry=><div className="history" key={entry.id}><b>{entry.action}</b><small>{entry.actor} · {new Date(entry.created_at+'Z').toLocaleString()}</small></div>)}</section>;
}
function DataStatus(){
 const {data,error}=useQuery({queryKey:['admin-data'],queryFn:()=>get<{status:string;engine:string;database:string;version?:string}>('/admin/data'),retry:false});
 return <section className="panel">{error?<p role="alert">{errorText(error)}</p>:data?<><p>Состояние · {data.status==='ok'?'Доступна':data.status}</p><p>База · {data.database}</p><p>Движок · {data.engine} {data.version}</p></>:<p>Загрузка…</p>}</section>;
}
function SystemSettings({run}:{run:Run}){
 const {data,error}=useQuery({queryKey:['admin-settings'],queryFn:()=>get<{integration_mode:string}>('/admin/settings')});
 return <section className="panel"><h2>Интеграция с 1С УТ</h2>{error?<p role="alert">{errorText(error)}</p>:data?
 <form key={data.integration_mode} onSubmit={e=>{e.preventDefault();const mode=new FormData(e.currentTarget).get('mode');void run(()=>post('/admin/settings',{integration_mode:mode}),'Режим сохранён')}}>
 <label>Режим<select name="mode" defaultValue={data.integration_mode}><option value="MOCK">Симулятор</option><option value="REAL">Согласованный сервис 1С</option></select></label>
 <p>Адрес и реквизиты подключения задаются в окружении сервера.</p><button>Сохранить настройки</button></form>:<p>Загрузка…</p>}</section>;
}
function RoleGrants({user,departments,run}:{user:Person;departments:Dept[];run:Run}){const {data:grants=[]}=useQuery({queryKey:['grants',user.id],queryFn:()=>get<RoleGrant[]>(`/users/${user.id}/grants`)});return <div className="history"><b>{user.login}</b>{grants.map((g,i)=><div className="row" key={i}><span>{roleLabel(g.role)} · {departments.find(d=>d.id===g.department_id)?.name||'без отдела'}</span><button type="button" className="secondary" onClick={()=>run(()=>post(`/users/${user.id}/grants`,{grants:grants.filter((_,index)=>index!==i)}),'Роль снята')}>Снять</button></div>)}<form className="record" onSubmit={e=>{e.preventDefault();const f=new FormData(e.currentTarget);run(()=>post(`/users/${user.id}/grants`,{grants:[...grants,{role:f.get('role'),department_id:f.get('department')?Number(f.get('department')):null}]}),'Роль добавлена')}}><select name="role" aria-label={`Дополнительная роль ${user.login}`}>{accountRoles.map(r=><option key={r} value={r}>{roleLabel(r)}</option>)}</select><select name="department" aria-label={`Отдел для ${user.login}`}><option value="">Без отдела</option>{departments.filter(d=>d.active).map(d=><option key={d.id} value={d.id}>{d.name}</option>)}</select><button>Добавить роль</button></form></div>}
function Settings({run,companyAdmin,systemAdmin}:{run:Run;companyAdmin:boolean;systemAdmin:boolean}){
 const {data:categories=[]}=useQuery({queryKey:['categories'],queryFn:()=>get<Category[]>('/categories')});
 const {data:departments=[]}=useQuery({queryKey:['departments'],queryFn:()=>get<Dept[]>('/departments')});
 const {data:routes=[],error}=useQuery({queryKey:['category-routes'],queryFn:()=>get<CategoryRoute[]>('/workflow/routes'),enabled:companyAdmin||systemAdmin});
 return <>
  <section className="panel"><h2>Категории</h2>
   <form className="record" onSubmit={e=>{
    e.preventDefault();const form=e.currentTarget, fields=new FormData(form);
    void run(async()=>{await post('/categories',{name:fields.get('name'),active:true});form.reset();},'Категория добавлена');
   }}><input name="name" aria-label="Название категории" placeholder="Название категории" required/><button>Добавить</button></form>
   {categories.map(category=><form className="record" key={category.id} onSubmit={e=>{
    e.preventDefault();const fields=new FormData(e.currentTarget);
    void run(()=>post('/categories/'+category.id,{name:fields.get('name'),active:fields.has('active')}),'Категория сохранена');
   }}>
    <input name="name" aria-label={'Название '+category.name} defaultValue={category.name} required/>
    <label className="check"><input name="active" type="checkbox" defaultChecked={category.active}/>Активна</label>
    <button className="secondary">Сохранить</button>
   </form>)}
  </section>
  {error&&<p role="alert">{errorText(error)}</p>}
  {(companyAdmin||systemAdmin)&&<RouteVersions categories={categories} departments={departments} routes={routes}
   publish={companyAdmin?(category,department)=>void run(()=>post('/workflow/routes',{category_id:category,department_id:department}),'Маршрут опубликован'):undefined}
   disable={companyAdmin?category=>void run(()=>post('/workflow/routes/'+category+'/disable',{}),'Маршрут отключён'):undefined}/>}
 </>;
}

function DepartmentOffices({run}:{run:Run}){
 const {data=[],error,isPending}=useQuery({queryKey:['offices'],queryFn:()=>get<Office[]>('/workflow/offices')});
 if(error)return <p role="alert">{errorText(error)}</p>;
 if(isPending)return <p>Загрузка…</p>;
 return <Offices offices={data} save={(id,head,deputy)=>void run(
  ()=>post('/workflow/offices/'+id,{head_id:head,deputy_id:deputy}),'Назначения сохранены'
 )}/>;
}

function Appeals({open}:{open:(id:number)=>void}){
 const {data=[],error,isPending}=useQuery({queryKey:['appeals'],queryFn:()=>get<AppealQueueEntry[]>('/workflow/appeals')});
 if(error)return <p role="alert">{errorText(error)}</p>;
 if(isPending)return <p>Загрузка…</p>;
 return <AppealQueue entries={data} open={open}/>;
}

function RoutingIssues(){
 const {data,error}=useQuery({queryKey:['routing-issues'],queryFn:()=>get<{current:RoutingIssue[];history:RoutingIssue[]}>('/workflow/issues')});
 if(error)return <p role="alert">{errorText(error)}</p>;
 if(!data)return <p>Загрузка…</p>;
 return <><section className="panel"><h2>Текущие ошибки настройки</h2>
  {data.current.map(issue=><div className="history" key={issue.category}><b>{issue.category}</b><p>{issue.reason}</p></div>)}
  {!data.current.length&&<p>Ошибок настройки нет.</p>}
 </section><section className="panel"><h2>Журнал ошибок подачи</h2>
  {data.history.map(issue=><div className="history" key={issue.id}><b>{issue.category}</b><p>{issue.reason}</p><small>{issue.created_at}</small></div>)}
  {!data.history.length&&<p>Ошибок подачи нет.</p>}
 </section></>;
}
function Notifications({run,open}:{run:Run;open:(id:number)=>void}){const {data=[]}=useQuery({queryKey:['notifications'],queryFn:()=>get<Note[]>('/notifications')});return <section className="panel"><h2>Уведомления</h2>{data.map(n=><div className="record" key={n.id}>{n.ticket_id!==null?<button className="secondary" onClick={()=>open(n.ticket_id!)}>{n.message}</button>:<span>{n.message}</span>}<span>{n.read?'Прочитано':'Новое'}</span>{!n.read&&<button className="secondary" onClick={()=>run(()=>post(`/notifications/${n.id}/read`,{}),'Прочитано')}>Отметить прочитанным</button>}</div>)}{!data.length&&<p>Уведомлений пока нет.</p>}</section>}
if(import.meta.env.MODE!=='test')createRoot(document.getElementById('root')!).render(<React.StrictMode><QueryClientProvider client={new QueryClient()}><BrowserRouter><App/></BrowserRouter></QueryClientProvider></React.StrictMode>);
