export const csrf=()=>document.cookie.split('; ').find(x=>x.startsWith('mailmcp_csrf='))?.split('=')[1]??''
export async function api<T>(path:string,init:RequestInit={}):Promise<T>{
 const headers=new Headers(init.headers); if(init.body)headers.set('Content-Type','application/json'); if(!['GET','HEAD'].includes(init.method??'GET'))headers.set('X-CSRF-Token',decodeURIComponent(csrf()))
 const response=await fetch(`/api${path}`,{...init,headers,credentials:'same-origin'}); if(!response.ok)throw new Error((await response.json().catch(()=>({}))).detail??`HTTP ${response.status}`); if(response.status===204)return undefined as T; return response.json()
}
