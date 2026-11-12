// @vitest-environment jsdom
import React from 'react';
import {describe,it,expect,vi,afterEach} from 'vitest';
import {render,screen,fireEvent,waitFor,cleanup} from '@testing-library/react';
import {QueryClient,QueryClientProvider} from '@tanstack/react-query';
const mock=vi.hoisted(()=>({get:vi.fn(),post:vi.fn()}));
vi.mock('axios',()=>({default:{create:()=>({get:mock.get,post:mock.post,interceptors:{request:{use:vi.fn()},response:{use:vi.fn()}}}),isAxiosError:()=>false}}));
import {App} from './main';
afterEach(()=>{cleanup();vi.clearAllMocks()});
describe('session isolation',()=>{
 it('clears the one-time anonymous token on logout before another user logs in',async()=>{
  mock.get.mockImplementation(async(p:string)=>{if(p==='/me')throw Error('no session');if(p==='/tickets')return {data:[]};if(p==='/categories')return {data:[{id:1,name:'Оборудование',active:true}]};if(p==='/departments')return {data:[]};return {data:[]}});
  mock.post.mockImplementation(async(p:string,d:any)=>{if(p==='/login')return {data:{login:d.login,role:d.login==='employee'?'EMPLOYEE':'SUPER_ADMIN',csrf:'csrf'}};if(p==='/tickets')return {data:{anonymous_token:'one-time-secret-token'}};return {data:{ok:true}}});
  render(<QueryClientProvider client={new QueryClient({defaultOptions:{queries:{retry:false}}})}><App/></QueryClientProvider>);
  await screen.findByText('Добро пожаловать');
  fireEvent.change(screen.getByLabelText('Логин'),{target:{value:'employee'}});fireEvent.change(screen.getByLabelText('Пароль'),{target:{value:'test-password'}});fireEvent.click(screen.getByText('Войти'));
  await screen.findByText('Новое обращение');fireEvent.click(screen.getByText('Новое обращение'));
  fireEvent.change(screen.getByLabelText('Заголовок'),{target:{value:'Сканер'}});fireEvent.change(screen.getByLabelText('Описание'),{target:{value:'Сканер не работает'}});await screen.findByText('Оборудование');fireEvent.change(screen.getByRole('combobox',{name:'Категория'}),{target:{value:'Оборудование'}});fireEvent.click(screen.getByLabelText('Отправить анонимно'));fireEvent.click(screen.getByText('Отправить'));
  await screen.findByText('one-time-secret-token');fireEvent.click(screen.getByText('Выйти'));
  await screen.findByText('Добро пожаловать');fireEvent.change(screen.getByLabelText('Логин'),{target:{value:'admin'}});fireEvent.change(screen.getByLabelText('Пароль'),{target:{value:'test-password'}});fireEvent.click(screen.getByText('Войти'));
  await waitFor(()=>expect(screen.getByRole('button',{name:'Профиль · admin'})).toBeTruthy());expect(screen.queryByText('one-time-secret-token')).toBeNull();expect(screen.queryByText('Анонимный доступ')).toBeNull();
 });
 it('switches only to a role returned by the server and clears the previous view',async()=>{
  const roles=[{role:'EMPLOYEE',department_id:null},{role:'DEPARTMENT_MANAGER',department_id:1}];
  mock.get.mockImplementation(async(p:string)=>p==='/me'?{data:{login:'dual',role:'EMPLOYEE',department_id:null,roles,csrf:'csrf'}}:{data:[]});
  mock.post.mockImplementation(async(p:string,d:any)=>p==='/session/role'?{data:{login:'dual',role:d.role,department_id:d.department_id,roles,csrf:'csrf'}}:{data:{}});
  render(<QueryClientProvider client={new QueryClient({defaultOptions:{queries:{retry:false}}})}><App/></QueryClientProvider>);
  await screen.findByText('Новое обращение');fireEvent.click(screen.getByText('Новое обращение'));
  fireEvent.change(screen.getByLabelText('Рабочая роль'),{target:{value:JSON.stringify(roles[1])}});
  await waitFor(()=>expect(mock.post).toHaveBeenCalledWith('/session/role',roles[1]));
  await waitFor(()=>expect(screen.queryByText('Новое обращение')).toBeNull());
  expect((screen.getByLabelText('Рабочая роль') as HTMLSelectElement).value).toBe(JSON.stringify(roles[1]));
 });
});


it('opens administration immediately and changes the password from the profile',async()=>{
 mock.get.mockImplementation(async(path:string)=>path==='/me'?
  {data:{login:'Smeil',role:'SUPER_ADMIN',csrf:'csrf'}}:{data:[]});
 mock.post.mockResolvedValue({data:{ok:true}});
 render(<QueryClientProvider client={new QueryClient({defaultOptions:{queries:{retry:false}}})}><App/></QueryClientProvider>);
 await screen.findByRole('button',{name:'Управление пользователями'});
 expect(screen.queryByLabelText('Текущий пароль')).toBeNull();
 fireEvent.click(screen.getByRole('button',{name:'Профиль · Smeil'}));
 fireEvent.change(screen.getByLabelText('Текущий пароль'),{target:{value:'temporary-test-password'}});
 fireEvent.change(screen.getByLabelText('Новый пароль',{exact:true}),{target:{value:'permanent-test-password'}});
 fireEvent.change(screen.getByLabelText('Подтверждение нового пароля'),{target:{value:'permanent-test-password'}});
 fireEvent.click(screen.getByRole('button',{name:'Сохранить новый пароль'}));
 await screen.findByText('Пароль изменён');
 expect(mock.post).toHaveBeenCalledWith('/password',{
  current_password:'temporary-test-password',password:'permanent-test-password',confirmation:'permanent-test-password',
 });
});
