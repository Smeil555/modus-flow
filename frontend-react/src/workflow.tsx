import React, {useState} from 'react';

export const leaders = ['DEPARTMENT_MANAGER', 'DEPARTMENT_DEPUTY'];
export const administrators = ['ADMIN', 'ADMIN_ASSISTANT'];
export const statuses: Record<string, string> = {
  NEW: 'Новое', ASSIGNED: 'На рассмотрении', IN_PROGRESS: 'В работе',
  NEEDS_INFO: 'Ожидает уточнения', RESOLVED: 'Реализовано', CLOSED: 'Закрыто',
  REJECTED: 'Отклонено', APPEAL: 'Пересмотр отказа',
};

export type Department = {id: number; name: string; active: boolean; description: string};
export type Category = {id: number; name: string; active: boolean};
export type Candidate = {id: number; login: string; eligible_worker?: boolean};
type ActionName = 'accept' | 'redirect' | 'assign' | 'return' | 'clarify' | 'answer' |
  'submit_result' | 'confirm' | 'close' | 'refuse' | 'feedback' | 'appeal' | 'admit' | 'claim' | 'vote';
export type ActionPayload = {action: ActionName; record_version: number; reason?: string; description?: string;
  department_id?: number; executor_id?: number; due_at?: string; decision?: string};
type Appeal = {
  id: number; motivation: string; admission_decision: string; admission_reason?: string;
  joint_outcome?: string; manager_position?: string; admin_position?: string; manager_reason?: string; admin_reason?: string;
};
export type WorkflowCase = {
  id: number; status: string; kind?: string; record_version: number;
  access?: 'internal' | 'author' | 'appeal' | 'oversight';
  actions?: ActionName[]; can_edit?: boolean; can_comment?: boolean; can_attach?: boolean; can_mark_implemented?: boolean;
  owner_id?: number; executor_id?: number | null; department_id?: number | null; due_at?: string | null;
  clarifications?: {id: number; question: string; answer?: string | null}[];
  work_results?: {id: number; description: string; outcome: string; confirmed: boolean; superseded: boolean}[];
  refusals?: {id: number; reason: string; appeals: Appeal[]}[];
};

const actionLabels: Record<ActionName, string> = {
  accept: 'Принять на рассмотрение', redirect: 'Перенаправить', assign: 'Назначение и срок',
  return: 'Вернуть на рассмотрение', clarify: 'Запросить уточнение', answer: 'Ответить на уточнение',
  submit_result: 'Передать результат', confirm: 'Подтвердить результат', close: 'Закрыть обращение',
  refuse: 'Оформить отказ', feedback: 'Обработать положительный отзыв', appeal: 'Запросить пересмотр отказа',
  admit: 'Решить вопрос допуска', claim: 'Участвовать в пересмотре', vote: 'Зафиксировать позицию',
};
const reasonLabels: Partial<Record<ActionName, string>> = {
  redirect: 'Причина перенаправления', return: 'Причина возврата', clarify: 'Вопрос автору', answer: 'Ответ автора',
  submit_result: 'Результат выполнения', refuse: 'Причина отказа', feedback: 'Как обработан отзыв',
  appeal: 'Почему решение следует пересмотреть', admit: 'Обоснование допуска', vote: 'Обоснование позиции',
};
const decisionLabels: Record<string, string> = {
  PENDING: 'Ожидает допуска', ALLOW: 'Допущен', DENY: 'В допуске отказано',
  REOPEN: 'Возобновить рассмотрение', UPHOLD: 'Подтвердить отказ',
};

function localDate(value?: string | null) {
  if (!value) return '';
  const date = new Date(value.endsWith('Z') ? value : value + 'Z');
  return new Date(date.getTime() - date.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
}

export function CaseActions({ticket, departments = [], workers = [], save}: {
  ticket: WorkflowCase; departments?: Department[]; workers?: Candidate[];
  save: (data: ActionPayload) => Promise<boolean>;
}) {
  const [selected, setSelected] = useState<ActionName>();
  const [busy, setBusy] = useState(false);
  const available = ticket.actions ?? [];
  const action = selected && available.includes(selected) ? selected : undefined;
  if (!available.length) return null;
  return <section className="panel">
    <h2>Действия с обращением</h2>
    <div className="row">
      {available.map(name => <button key={name} type="button" className="secondary" aria-pressed={name === action}
        disabled={busy} onClick={() => setSelected(name)}>{actionLabels[name]}</button>)}
    </div>
    {action && <form key={action} className="workflow-form" onSubmit={async event => {
      event.preventDefault();
      const fields = new FormData(event.currentTarget);
      const data: ActionPayload = {action, record_version: ticket.record_version};
      if (fields.has('reason')) data.reason = String(fields.get('reason'));
      if (fields.has('description')) data.description = String(fields.get('description'));
      if (fields.has('department')) data.department_id = Number(fields.get('department'));
      if (fields.has('executor')) data.executor_id = Number(fields.get('executor'));
      if (fields.has('due')) data.due_at = new Date(String(fields.get('due'))).toISOString();
      if (fields.has('decision')) data.decision = String(fields.get('decision'));
      setBusy(true);
      try { if (await save(data)) setSelected(undefined); } finally { setBusy(false); }
    }}>
      {action === 'redirect' && <label>Новый отдел<select name="department" required defaultValue="">
        <option value="" disabled>Выберите отдел</option>
        {departments.filter(d => d.active && d.id !== ticket.department_id).map(d => <option key={d.id} value={d.id}>{d.name}</option>)}
      </select></label>}
      {action === 'assign' && <>
        <label>Исполнитель<select name="executor" required defaultValue={ticket.executor_id ?? ''}>
          <option value="" disabled>Выберите сотрудника</option>
          {workers.filter(user => user.eligible_worker).map(user => <option key={user.id} value={user.id}>{user.login}</option>)}
        </select></label>
        <label>Срок выполнения<input name="due" type="datetime-local" required defaultValue={localDate(ticket.due_at)}/></label>
      </>}
      {(action === 'admit' || action === 'vote') && <label>Решение<select name="decision" required defaultValue="">
        <option value="" disabled>Выберите решение</option>
        {(action === 'admit' ? ['ALLOW', 'DENY'] : ['REOPEN', 'UPHOLD']).map(value =>
          <option key={value} value={value}>{decisionLabels[value]}</option>)}
      </select></label>}
      {(action === 'appeal' || action === 'submit_result') && <label>
        {action === 'appeal' ? 'С чем вы не согласны' : 'Описание выполненной работы'}
        <textarea name="description" required maxLength={5000}/>
      </label>}
      {reasonLabels[action] && <label>{reasonLabels[action]}<textarea name="reason" required maxLength={5000}/></label>}
      <button disabled={busy}>Сохранить действие</button>
    </form>}
  </section>;
}

export function CaseRecords({ticket}: {ticket: WorkflowCase}) {
  return <>
    {!!ticket.clarifications?.length && <section className="panel">
      <h2>Уточнения</h2>
      {ticket.clarifications.map(item => <div className="history" key={item.id}>
        <b>Вопрос</b><p>{item.question}</p><b>Ответ</b><p>{item.answer ?? 'Ожидается ответ автора'}</p>
      </div>)}
    </section>}
    {!!ticket.work_results?.length && <section className="panel">
      <h2>Результаты работы</h2>
      {ticket.work_results.map(item => <div className="history" key={item.id}>
        <b>{item.confirmed ? 'Подтверждён' : item.superseded ? 'Заменён' : 'Ожидает подтверждения'}</b>
        <p>{item.description}</p><p>{item.outcome}</p>
      </div>)}
    </section>}
    {!!ticket.refusals?.length && <section className="panel">
      <h2>Отказы и пересмотры</h2>
      {ticket.refusals.map(refusal => <div key={refusal.id} className="history">
        <b>Решение об отказе № {refusal.id}</b><p>{refusal.reason}</p>
        {refusal.appeals.map(appeal => <div key={appeal.id} className="history">
          <b>Запрос № {appeal.id} · {decisionLabels[appeal.admission_decision]}</b>
          <p>{appeal.motivation}</p>
          {appeal.admission_reason && <p>Решение о допуске — {appeal.admission_reason}</p>}
          {appeal.manager_reason && <p>Позиция отдела — {appeal.manager_reason}</p>}
          {appeal.admin_reason && <p>Позиция администрации — {appeal.admin_reason}</p>}
          {appeal.joint_outcome && <p>Совместный итог — {decisionLabels[appeal.joint_outcome]}</p>}
        </div>)}
      </div>)}
    </section>}
  </>;
}

export type Office = {
  id: number; name: string; active: boolean; head_id: number | null; deputy_id: number | null; owner_id: number | null; people: Candidate[];
};
export type CategoryRoute = {
  id: number; category_id: number; department_id: number; version: number; active: boolean; valid_from: string | null; valid_to: string | null;
};
export type RoutingIssue = {id?: number; category: string; reason: string; created_at?: string};
export type AppealQueueEntry = {id: number; ticket_id: number; number: string; refusal_id: number; category: string;
  admission_decision: string; assigned: boolean};

export function Offices({offices, save}: {offices: Office[]; save: (id: number, head: number | null, deputy: number | null) => void}) {
  return <section className="panel">
    <h2>Руководители и заместители</h2>
    {offices.filter(office => office.active).map(office => <form key={[office.id, office.head_id, office.deputy_id].join(':')}
      className="record" onSubmit={event => {
        event.preventDefault();
        const data = new FormData(event.currentTarget);
        save(office.id, Number(data.get('head')) || null, Number(data.get('deputy')) || null);
      }}>
      <div><b>{office.name}</b><p>{office.owner_id ? 'Есть действующий ответственный' : 'Ответственный отсутствует'}</p></div>
      <label>Руководитель<select name="head" defaultValue={office.head_id ?? ''}>
        <option value="">Не назначен</option>
        {office.people.map(person => <option key={person.id} value={person.id}>{person.login}</option>)}
        {office.head_id && !office.people.some(person => person.id === office.head_id) &&
          <option value={office.head_id}>Недоступен (ID {office.head_id})</option>}
      </select></label>
      <label>Заместитель<select name="deputy" defaultValue={office.deputy_id ?? ''}>
        <option value="">Не назначен</option>
        {office.people.map(person => <option key={person.id} value={person.id}>{person.login}</option>)}
        {office.deputy_id && !office.people.some(person => person.id === office.deputy_id) &&
          <option value={office.deputy_id}>Недоступен (ID {office.deputy_id})</option>}
      </select></label>
      <button>Сохранить назначения</button>
    </form>)}
  </section>;
}

export function RouteVersions({categories, departments, routes, publish, disable}: {
  categories: Category[]; departments: Department[]; routes: CategoryRoute[];
  publish?: (category: number, department: number) => void; disable?: (category: number) => void;
}) {
  return <section className="panel">
    <h2>Версии маршрутов</h2>
    {publish && <form className="record" onSubmit={event => {
      event.preventDefault();
      const data = new FormData(event.currentTarget);
      publish(Number(data.get('category')), Number(data.get('department')));
    }}>
      <label>Категория<select name="category" required defaultValue=""><option value="" disabled>Выберите категорию</option>
        {categories.filter(category => category.active).map(category => <option key={category.id} value={category.id}>{category.name}</option>)}
      </select></label>
      <label>Принимающий отдел<select name="department" required defaultValue=""><option value="" disabled>Выберите отдел</option>
        {departments.filter(department => department.active).map(department => <option key={department.id} value={department.id}>{department.name}</option>)}
      </select></label>
      <button>Опубликовать маршрут</button>
    </form>}
    {!routes.length && <p>Маршруты ещё не опубликованы.</p>}
    {routes.map(route => <div className="record" key={route.id}>
      <div><b>{categories.find(category => category.id === route.category_id)?.name ?? route.category_id}</b>
        <p>{departments.find(department => department.id === route.department_id)?.name ?? route.department_id} · Версия {route.version}</p>
        <small>{route.active ? 'Действует' : 'Архив'} · {route.valid_from && new Date(route.valid_from + 'Z').toLocaleString()}
          {route.valid_to && ' — ' + new Date(route.valid_to + 'Z').toLocaleString()}</small>
      </div>
      {route.active && disable && <button className="secondary" onClick={() => disable(route.category_id)}>Отключить маршрут</button>}
    </div>)}
  </section>;
}

export function AppealQueue({entries, open}: {entries: AppealQueueEntry[]; open: (id: number) => void}) {
  return <>{[true, false].map(pending => <section key={String(pending)} className="panel">
    <h2>{pending ? 'Повторные запросы на допуск' : 'Совместные пересмотры'}</h2>
    {entries.filter(item => (item.admission_decision === 'PENDING') === pending).map(item =>
      <button key={item.id} className="ticket" onClick={() => open(item.ticket_id)}>
        <span>{item.number} · {item.category} · Отказ № {item.refusal_id}</span>
        <span className="badge">{item.assigned ? 'Вы участвуете' : decisionLabels[item.admission_decision]}</span>
      </button>)}
    {!entries.some(item => (item.admission_decision === 'PENDING') === pending) && <p>Открытых запросов нет.</p>}
  </section>)}</>;
}
