export const csrf=()=>document.cookie.split('; ').find(x=>x.startsWith('mailmcp_csrf='))?.split('=')[1]??''
type ApiErrorDetail={loc?:Array<string|number>;msg?:string;message?:string}
export function errorMessage(payload:unknown,status:number):string{
 if(payload&&typeof payload==='object'&&'detail'in payload){
  const detail=(payload as {detail:unknown}).detail
  if(Array.isArray(detail))return detail.map((item:ApiErrorDetail)=>{const field=item.loc?.filter(x=>x!=='body').join('.')||'requête';return `${field} : ${item.msg??item.message??'valeur invalide'}`}).join(' · ')
  if(typeof detail==='string')return detail
  if(detail&&typeof detail==='object')return JSON.stringify(detail)
 }
 return `Erreur HTTP ${status}`
}
export async function api<T>(path:string,init:RequestInit={}):Promise<T>{
 const headers=new Headers(init.headers); if(init.body)headers.set('Content-Type','application/json'); if(!['GET','HEAD'].includes(init.method??'GET'))headers.set('X-CSRF-Token',decodeURIComponent(csrf()))
 const response=await fetch(`/api${path}`,{...init,headers,credentials:'same-origin'}); if(!response.ok){const payload:unknown=await response.json().catch(()=>null);throw new Error(errorMessage(payload,response.status))} if(response.status===204)return undefined as T; return response.json()
}
