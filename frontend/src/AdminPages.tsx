import {FormEvent, useEffect, useMemo, useState} from 'react'
import {Activity, Archive, ChevronRight, Edit3, KeyRound, Plus, RefreshCw, Star, Trash2, X} from 'lucide-react'
import {api} from './api'
import type {Account, Dashboard} from './types'

type Go = (page:string)=>void
type ApiResult<T>={success:boolean;data:T;errors?:string[];partial?:boolean}
type Permission={name:string;mutating:boolean;destructive:boolean}
type Mailbox={canonical_name:string;display_name:string;delimiter:string|null;flags:string[];special_use:string|null;subscribed:boolean}
type MessageRow={uid:number;mailbox:string;subject:string;sender:string;date:string;size:number;seen:boolean;flagged:boolean;has_attachment:boolean}
type Diagnostic={status:string;error?:string;details?:unknown;errors?:string[];url?:string;duration_ms?:number}

const message=(error:unknown)=>error instanceof Error?error.message:String(error)
const accountPath=(name:string)=>'/accounts/'+encodeURIComponent(name)

function Header({eyebrow,title,text,action}:{eyebrow:string;title:string;text:string;action?:React.ReactNode}){
 return <div className="page-head"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p>{text}</p></div>{action}</div>
}
function Empty({title,text}:{title:string;text:string}){return <div className="empty"><Archive/><b>{title}</b><p>{text}</p></div>}
function Notice({text,error=false}:{text:string;error?:boolean}){return text?<div className={error?'error block':'notice'}>{text}</div>:null}

export function DashboardManagerPage({go}:{go:Go}){
 const [data,setData]=useState<Dashboard|null>(null),[error,setError]=useState('')
 useEffect(()=>{api<Dashboard>('/dashboard').then(setData).catch(e=>setError(message(e)))},[])
 if(error)return <Empty title="Dashboard indisponible" text={error}/>
 if(!data)return <Empty title="Chargement" text="Lecture de l’état du serveur…"/>
 const uptime=(s:number)=>{const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);return d+'j '+h+'h '+m+'m'}
 return <><Header eyebrow="Vue d’ensemble" title="Bonjour, Administrateur" text="État de votre infrastructure Mail MCP en temps réel."/>
  <div className="stats">
   <article className="stat"><div className="dot green"/><div><span>Serveur</span><strong>{data.status==='ok'?'Opérationnel':'Erreur'}</strong><small>Uptime {uptime(data.uptime_seconds)}</small></div></article>
   <article className="stat"><div className="dot"/><div><span>Version</span><strong>v{data.version}</strong><small>Streamable HTTP natif</small></div></article>
   <article className="stat"><div className="dot violet"/><div><span>Comptes</span><strong>{data.accounts}</strong><small>{data.default_account?'Défaut : '+data.default_account:'Aucun compte par défaut'}</small></div></article>
   <article className="stat"><div className="dot amber"/><div><span>Opérations MCP</span><strong>{data.recent_operations}</strong><small>Journalisées</small></div></article>
  </div>
  <div className="grid"><section className="panel wide"><h3>État des services</h3><div className="services">
   {[['Base de données',data.database,data.database?'Connexion active':'Indisponible'],['Endpoint MCP',true,data.mcp_url],['Mode d’écriture',!data.read_only,data.read_only?'Lecture seule':'Opérations autorisées']].map(([name,ok,detail])=><div className="service" key={String(name)}><span className={ok?'up':'down'}>{ok?'✓':'×'}</span><div><b>{String(name)}</b><small>{String(detail)}</small></div><em>{ok?'OPÉRATIONNEL':'ATTENTION'}</em></div>)}
  </div></section><section className="panel"><h3>Accès rapide</h3><div className="quick"><button onClick={()=>go('Comptes mail')}>Configurer un compte <Plus/></button><button onClick={()=>go('Diagnostics')}>Lancer un diagnostic <Activity/></button><button onClick={()=>go('Test MCP')}>Tester MCP <ChevronRight/></button></div></section>
  <section className="panel wide"><h3>Dernières erreurs</h3>{data.last_errors.filter(Boolean).length?<ul>{data.last_errors.map((e,i)=><li key={i}>{e}</li>)}</ul>:<Empty title="Aucune erreur récente" text="Tout fonctionne normalement."/>}</section></div></>
}

const blankAccount={name:'',display_name:'',email:'',enabled:true,is_default:false,imap_host:'',imap_port:993,imap_ssl:true,imap_username:'',smtp_host:'',smtp_port:465,smtp_ssl:true,smtp_starttls:false,smtp_username:'',sent_mailbox:'',drafts_mailbox:'',trash_mailbox:'',archive_mailbox:'',junk_mailbox:''}
function AccountModal({account,close,saved}:{account:Account|null;close:()=>void;saved:()=>void}){
 const editing=!!account,[notice,setNotice]=useState(''),[busy,setBusy]=useState(false),initial=account??blankAccount
 async function submit(event:FormEvent<HTMLFormElement>){
  event.preventDefault();setBusy(true);setNotice('');const form=new FormData(event.currentTarget)
  const payload:Record<string,unknown>={}
  for(const key of ['display_name','email','imap_host','imap_username','smtp_host','smtp_username','sent_mailbox','drafts_mailbox','trash_mailbox','archive_mailbox','junk_mailbox'])payload[key]=String(form.get(key)??'')||null
  payload.imap_port=Number(form.get('imap_port'));payload.smtp_port=Number(form.get('smtp_port'))
  for(const key of ['enabled','is_default','imap_ssl','smtp_ssl','smtp_starttls'])payload[key]=form.get(key)==='on'
  const imapPassword=String(form.get('imap_password')??''),smtpPassword=String(form.get('smtp_password')??'')
  if(imapPassword)payload.imap_password=imapPassword;if(smtpPassword)payload.smtp_password=smtpPassword
  if(!editing)payload.name=String(form.get('name')??'')
  try{await api(editing?accountPath(account.name):'/accounts',{method:editing?'PATCH':'POST',body:JSON.stringify(payload)});saved()}catch(e){setNotice(message(e))}finally{setBusy(false)}
 }
 return <div className="modal-bg"><form className="modal" onSubmit={submit}><button type="button" className="close" onClick={close}><X/></button><div className="eyebrow">{editing?'MODIFIER LE COMPTE':'NOUVELLE CONNEXION'}</div><h2>{editing?account.display_name:'Ajouter un compte mail'}</h2>
  <div className="form-grid">{!editing&&<label>Nom interne<input name="name" required/></label>}<label>Nom affiché<input name="display_name" defaultValue={initial.display_name} required/></label><label>Adresse email<input name="email" type="email" defaultValue={initial.email} required/></label><label>Hôte IMAP<input name="imap_host" defaultValue={initial.imap_host} required/></label><label>Port IMAP<input name="imap_port" type="number" min="1" max="65535" defaultValue={initial.imap_port} required/></label><label>Utilisateur IMAP<input name="imap_username" defaultValue={initial.imap_username} required/></label><label>Mot de passe IMAP<input name="imap_password" type="password" required={!editing} placeholder={editing?'Laisser vide pour conserver':''}/></label><label>Hôte SMTP<input name="smtp_host" defaultValue={initial.smtp_host} required/></label><label>Port SMTP<input name="smtp_port" type="number" min="1" max="65535" defaultValue={initial.smtp_port} required/></label><label>Utilisateur SMTP<input name="smtp_username" defaultValue={initial.smtp_username} required/></label><label>Mot de passe SMTP<input name="smtp_password" type="password" required={!editing} placeholder={editing?'Laisser vide pour conserver':''}/></label>
  {['sent','drafts','trash','archive','junk'].map(key=><label key={key}>Dossier {key}<input name={key+'_mailbox'} defaultValue={String((initial as unknown as Record<string,unknown>)[key+'_mailbox']??'')}/></label>)}</div>
  <div className="checks"><label><input type="checkbox" name="enabled" defaultChecked={initial.enabled}/> Actif</label><label><input type="checkbox" name="is_default" defaultChecked={initial.is_default}/> Par défaut</label><label><input type="checkbox" name="imap_ssl" defaultChecked={initial.imap_ssl}/> IMAP TLS</label><label><input type="checkbox" name="smtp_ssl" defaultChecked={initial.smtp_ssl}/> SMTP TLS</label><label><input type="checkbox" name="smtp_starttls" defaultChecked={initial.smtp_starttls}/> STARTTLS</label></div>
  <Notice text={notice} error/><div className="modal-actions"><button type="button" className="ghost" onClick={close}>Annuler</button><button className="primary" disabled={busy}>{busy?'Enregistrement…':'Enregistrer'}</button></div></form></div>
}

export function AccountsManagerPage(){
 const [items,setItems]=useState<Account[]>([]),[editing,setEditing]=useState<Account|null|undefined>(undefined),[notice,setNotice]=useState(''),[error,setError]=useState(false),[busy,setBusy]=useState('')
 const load=async()=>{try{setItems(await api<Account[]>('/accounts'));setError(false)}catch(e){setNotice(message(e));setError(true)}}
 useEffect(()=>{void load()},[])
 async function action(account:Account,kind:'default'|'detect'|'test'|'imap'|'smtp'|'delete'){
  if(kind==='delete'&&!confirm('Supprimer définitivement le compte '+account.display_name+' ?'))return
  setBusy(account.name+kind);setNotice('');setError(false)
  try{
   if(kind==='delete')await api(accountPath(account.name),{method:'DELETE'})
   else if(kind==='default')await api(accountPath(account.name)+'/default',{method:'POST'})
   else if(kind==='detect')await api(accountPath(account.name)+'/detect-folders',{method:'POST'})
   else {const suffix=kind==='test'?'/test':'/test-'+kind;const result=await api<ApiResult<unknown>>(accountPath(account.name)+suffix,{method:'POST'});if(!result.success)throw new Error((result.errors??['Test en échec']).join(' · '))}
   setNotice(kind==='delete'?'Compte supprimé.':kind==='detect'?'Dossiers détectés et enregistrés.':kind==='default'?'Compte défini par défaut.':'Connexion '+kind.toUpperCase()+' réussie.');await load()
  }catch(e){setNotice(message(e));setError(true)}finally{setBusy('')}
 }
 return <><Header eyebrow="Configuration" title="Comptes mail" text="Création, modification, tests IMAP/SMTP et dossiers spéciaux." action={<button className="primary" onClick={()=>setEditing(null)}><Plus/>Ajouter un compte</button>}/><Notice text={notice} error={error}/>
 <section className="panel table-panel"><table><thead><tr><th>Compte</th><th>Serveurs</th><th>État</th><th>Dossiers</th><th>Actions</th></tr></thead><tbody>{items.map(account=><tr key={account.id}><td><div className="account"><span>{account.display_name.slice(0,2).toUpperCase()}</span><div><b>{account.display_name}</b><small>{account.email}</small></div></div></td><td><b>{account.imap_host}:{account.imap_port}</b><small>{account.smtp_host}:{account.smtp_port}</small></td><td><span className={'pill '+(account.enabled?'ok':'')}>{account.enabled?'Actif':'Désactivé'}</span>{account.is_default&&<span className="pill default">Par défaut</span>}</td><td><small>{[account.sent_mailbox,account.drafts_mailbox,account.trash_mailbox,account.archive_mailbox,account.junk_mailbox].filter(Boolean).join(' · ')||'À détecter'}</small></td><td><div className="action-row"><button className="ghost" title="Modifier" onClick={()=>setEditing(account)}><Edit3/></button><button className="ghost" disabled={!account.enabled||account.is_default||!!busy} title="Définir par défaut" onClick={()=>action(account,'default')}><Star/></button><button className="ghost" disabled={!!busy} onClick={()=>action(account,'imap')}>IMAP</button><button className="ghost" disabled={!!busy} onClick={()=>action(account,'smtp')}>SMTP</button><button className="ghost" disabled={!!busy} onClick={()=>action(account,'test')}>Tous</button><button className="ghost" disabled={!!busy} onClick={()=>action(account,'detect')}>Dossiers</button><button className="danger" disabled={!!busy} title="Supprimer" onClick={()=>action(account,'delete')}><Trash2/></button></div></td></tr>)}{!items.length&&<tr><td colSpan={5}><Empty title="Aucun compte" text="Ajoutez votre premier compte IMAP/SMTP."/></td></tr>}</tbody></table></section>
 {editing!==undefined&&<AccountModal account={editing} close={()=>setEditing(undefined)} saved={()=>{setEditing(undefined);setNotice('Compte enregistré.');void load()}}/>}</>
}

export function ApiKeysManagerPage(){
 const [keys,setKeys]=useState<Array<{id:number;name:string;prefix:string;permissions:string[];enabled:boolean}>>([]),[permissions,setPermissions]=useState<Permission[]>([]),[selected,setSelected]=useState<Set<string>>(new Set(['read','attachments'])),[name,setName]=useState(''),[show,setShow]=useState(false),[revealed,setRevealed]=useState(''),[notice,setNotice]=useState('')
 const load=()=>Promise.all([api<typeof keys>('/api-keys'),api<Permission[]>('/permissions')]).then(([k,p])=>{setKeys(k);setPermissions(p)}).catch(e=>setNotice(message(e)))
 useEffect(()=>{void load()},[])
 function toggle(value:string){setSelected(old=>{const next=new Set(old);if(next.has(value))next.delete(value);else next.add(value);return next})}
 async function create(){if(!name.trim()||!selected.size)return;try{const row=await api<{key:string}>('/api-keys',{method:'POST',body:JSON.stringify({name:name.trim(),permissions:[...selected]})});setRevealed(row.key);setShow(false);setName('');await load()}catch(e){setNotice(message(e))}}
 async function remove(id:number){if(!confirm('Supprimer cette clé API ?'))return;try{await api('/api-keys/'+id,{method:'DELETE'});await load()}catch(e){setNotice(message(e))}}
 return <><Header eyebrow="Contrôle d’accès" title="Clés API" text="Permissions chargées directement depuis le backend." action={<button className="primary" onClick={()=>setShow(true)}><Plus/>Créer une clé</button>}/><Notice text={notice} error/>{revealed&&<div className="secret"><b>Copiez cette clé maintenant — elle ne sera plus affichée.</b><code>{revealed}</code></div>}
 <section className="panel table-panel"><table><thead><tr><th>Nom</th><th>Préfixe</th><th>Permissions</th><th>État</th><th/></tr></thead><tbody>{keys.map(key=><tr key={key.id}><td><b>{key.name}</b></td><td><code>{key.prefix}…</code></td><td>{key.permissions.map(p=><span className="pill" key={p}>{p}</span>)}</td><td><span className={'pill '+(key.enabled?'ok':'')}>{key.enabled?'Active':'Inactive'}</span></td><td><button className="danger" onClick={()=>remove(key.id)}><Trash2/></button></td></tr>)}</tbody></table></section>
 {show&&<div className="modal-bg"><div className="modal"><button className="close" onClick={()=>setShow(false)}><X/></button><div className="eyebrow">NOUVELLE CLÉ</div><h2>Permissions MCP</h2><label>Nom<input value={name} onChange={e=>setName(e.target.value)} autoFocus/></label><div className="permission-picker">{permissions.map(p=><label key={p.name} className={p.destructive?'destructive':''}><input type="checkbox" checked={selected.has(p.name)} onChange={()=>toggle(p.name)}/><span><code>{p.name}</code><small>{p.destructive?'Destructive':p.mutating?'Écriture':'Lecture'}</small></span></label>)}</div><div className="modal-actions"><button className="ghost" onClick={()=>setShow(false)}>Annuler</button><button className="primary" disabled={!name.trim()||!selected.size} onClick={create}><KeyRound/>Créer</button></div></div></div>}</>
}

export function MailBrowserManager({mode}:{mode:'folders'|'messages'}){
 const [accounts,setAccounts]=useState<Account[]>([]),[selected,setSelected]=useState(''),[mailbox,setMailbox]=useState('INBOX'),[folders,setFolders]=useState<Mailbox[]>([]),[messages,setMessages]=useState<MessageRow[]>([]),[error,setError]=useState(''),[refresh,setRefresh]=useState(0),[page,setPage]=useState(1)
 useEffect(()=>{api<Account[]>('/accounts').then(rows=>{setAccounts(rows);setSelected(rows.find(a=>a.is_default)?.name??rows[0]?.name??'')}).catch(e=>setError(message(e)))},[])
 useEffect(()=>{if(!selected)return;api<ApiResult<Mailbox[]>>(accountPath(selected)+'/mailboxes').then(r=>{setFolders(r.data);if(!r.data.some(x=>x.canonical_name===mailbox)&&r.data[0])setMailbox(r.data[0].canonical_name)}).catch(e=>setError(message(e)))},[selected,refresh])
 useEffect(()=>{if(mode!=='messages'||!selected||!mailbox)return;const query='?mailbox='+encodeURIComponent(mailbox)+'&page='+page+'&page_size=50';api<ApiResult<MessageRow[]>>(accountPath(selected)+'/messages'+query).then(r=>setMessages(r.data)).catch(e=>setError(message(e)))},[mode,selected,mailbox,page,refresh])
 return <><Header eyebrow="Messagerie" title={mode==='folders'?'Dossiers IMAP':'Messages'} text={mode==='folders'?'Dossiers canoniques et attributs RFC 6154.':'Consultation paginée par compte et dossier.'}/><div className="toolbar"><label>Compte<select value={selected} onChange={e=>{setSelected(e.target.value);setPage(1)}}>{accounts.map(a=><option key={a.id} value={a.name}>{a.display_name}</option>)}</select></label>{mode==='messages'&&<label>Dossier<select value={mailbox} onChange={e=>{setMailbox(e.target.value);setPage(1)}}>{folders.map(f=><option key={f.canonical_name} value={f.canonical_name}>{f.display_name}</option>)}</select></label>}<button className="ghost" onClick={()=>setRefresh(x=>x+1)}><RefreshCw/>Actualiser</button></div><Notice text={error} error/>
 <section className="panel table-panel">{mode==='folders'?<table><thead><tr><th>Nom</th><th>Canonique</th><th>Délimiteur</th><th>Usage</th><th>Abonné</th></tr></thead><tbody>{folders.map(f=><tr key={f.canonical_name}><td><b>{f.display_name}</b></td><td><code>{f.canonical_name}</code></td><td>{f.delimiter??'—'}</td><td><span className="pill">{f.special_use??'standard'}</span></td><td>{f.subscribed?'Oui':'Non'}</td></tr>)}</tbody></table>:<><table><thead><tr><th>UID</th><th>Expéditeur</th><th>Sujet</th><th>Date</th><th>État</th><th>Taille</th></tr></thead><tbody>{messages.map(m=><tr key={m.uid}><td><code>{m.uid}</code></td><td>{m.sender}</td><td><b>{m.subject||'(sans objet)'}</b></td><td>{m.date?new Date(m.date).toLocaleString('fr-BE'):'—'}</td><td>{m.seen?'Lu':'Non lu'} {m.flagged&&'★'} {m.has_attachment&&'📎'}</td><td>{Math.ceil(m.size/1024)} Ko</td></tr>)}</tbody></table><div className="pagination"><button className="ghost" disabled={page===1} onClick={()=>setPage(x=>Math.max(1,x-1))}>Précédent</button><span>Page {page}</span><button className="ghost" disabled={messages.length<50} onClick={()=>setPage(x=>x+1)}>Suivant</button></div></>}</section></>
}

export function DiagnosticsManagerPage(){
 const [accounts,setAccounts]=useState<Account[]>([]),[account,setAccount]=useState(''),[checks,setChecks]=useState<Record<string,Diagnostic>>({}),[busy,setBusy]=useState(false),[error,setError]=useState('')
 useEffect(()=>{api<Account[]>('/accounts').then(rows=>{setAccounts(rows);setAccount(rows.find(a=>a.is_default)?.name??rows[0]?.name??'')}).catch(e=>setError(message(e)))},[])
 async function run(){setBusy(true);setError('');try{const suffix=account?'?account_name='+encodeURIComponent(account):'';const result=await api<{checks:Record<string,Diagnostic>}>('/diagnostics'+suffix,{method:'POST'});setChecks(result.checks)}catch(e){setError(message(e))}finally{setBusy(false)}}
 const detail=(value:Diagnostic)=>value.error??value.errors?.join(' · ')??(typeof value.details==='string'?value.details:JSON.stringify(value.details??value.url??value.status))
 return <><Header eyebrow="Observabilité" title="Diagnostics" text="DNS, TCP, TLS, authentification mail, base et filesystem." action={<button className="primary" onClick={run} disabled={busy}><RefreshCw className={busy?'spin':''}/>{busy?'Analyse…':'Diagnostic complet'}</button>}/><div className="toolbar"><label>Compte testé<select value={account} onChange={e=>setAccount(e.target.value)}><option value="">Compte par défaut</option>{accounts.map(a=><option key={a.id} value={a.name}>{a.display_name}</option>)}</select></label></div><Notice text={error} error/><div className="diag">{Object.entries(checks).map(([key,value])=><div className="diag-row" key={key}><span className={value.status}>{value.status==='ok'?'✓':value.status==='warning'?'!':'×'}</span><div><b>{key.replaceAll('_',' ')}</b><small>{detail(value)}</small></div></div>)}{!Object.keys(checks).length&&<Empty title="Prêt à analyser" text="Choisissez un compte puis lancez le diagnostic."/>}</div></>
}

type FacebookProfile={id:string;label:string;default_page_id:string;pages:Array<{id:string;name:string;default:boolean}>}
type FacebookTokenStatus={has_token:boolean;status:string;expiry?:string;days_remaining?:number}
export function FacebookManagerPage(){
 const [profiles,setProfiles]=useState<FacebookProfile[]>([]),[token,setToken]=useState(''),[status,setStatus]=useState<FacebookTokenStatus|null>(null),[notice,setNotice]=useState(''),[error,setError]=useState(false),[busy,setBusy]=useState(false)
 const load=()=>Promise.all([api<{accounts:FacebookProfile[]}>('/facebook/config'),api<FacebookTokenStatus>('/facebook/token-status')]).then(([config,tokenStatus])=>{setProfiles(config.accounts);setStatus(tokenStatus)}).catch(e=>{setNotice(message(e));setError(true)})
 useEffect(()=>{void load()},[])
 function updateProfile(index:number,field:'label'|'default_page_id',value:string){setProfiles(rows=>rows.map((row,i)=>i===index?{...row,[field]:value}:row))}
 function updatePage(profileIndex:number,pageIndex:number,field:'id'|'name'|'default',value:string|boolean){setProfiles(rows=>rows.map((row,i)=>i!==profileIndex?row:{...row,pages:row.pages.map((page,j)=>j===pageIndex?{...page,[field]:value}:page)}))}
 async function save(){setBusy(true);setNotice('');try{await api('/facebook/config',{method:'POST',body:JSON.stringify({accounts:profiles})});setNotice('Profils et pages Facebook enregistrés.');setError(false);await load()}catch(e){setNotice(message(e));setError(true)}finally{setBusy(false)}}
 async function exchange(){if(!token.trim())return;setBusy(true);try{await api('/facebook/exchange-token',{method:'POST',body:JSON.stringify({short_lived_token:token.trim()})});setToken('');setNotice('Token échangé et stocké côté serveur.');setError(false);await load()}catch(e){setNotice(message(e));setError(true)}finally{setBusy(false)}}
 async function clear(){if(!confirm('Effacer le token Facebook stocké côté serveur ?'))return;setBusy(true);try{await api('/facebook/clear-token',{method:'POST'});setNotice('Token supprimé.');await load()}catch(e){setNotice(message(e));setError(true)}finally{setBusy(false)}}
 return <><Header eyebrow="Réseaux sociaux" title="Facebook" text="Les App ID et App Secret proviennent de l’environnement; aucun secret n’est réaffiché." action={<button className="primary" onClick={save} disabled={busy}>Enregistrer les profils</button>}/><Notice text={notice} error={error}/>
 <section className="panel"><h3>Token utilisateur longue durée</h3><p>Échangez un token court via les identifiants d’application configurés sur le serveur.</p><div className="token-exchange"><label>Token court<input type="password" value={token} onChange={e=>setToken(e.target.value)} placeholder="Token généré par Facebook"/></label><button className="primary" disabled={busy||!token.trim()} onClick={exchange}>Échanger</button>{status?.has_token&&<button className="danger" disabled={busy} onClick={clear}>Effacer</button>}</div>{status&&<div className="token-status"><span className={'pill '+(status.status==='valid'?'ok':'')}>{status.status}</span>{status.expiry&&<small>Expire le {new Date(status.expiry).toLocaleDateString('fr-BE')}</small>}{status.days_remaining!==undefined&&<small>{Math.floor(status.days_remaining)} jours restants</small>}</div>}</section>
 <section className="panel"><div className="toolbar"><button className="primary" onClick={()=>setProfiles(rows=>[...rows,{id:'facebook-'+Date.now(),label:'Facebook',default_page_id:'',pages:[]}])}><Plus/>Ajouter un profil</button></div>{profiles.length?<div className="profile-list">{profiles.map((profile,index)=><div className="profile" key={profile.id}><div className="profile-header"><input value={profile.label} onChange={e=>updateProfile(index,'label',e.target.value)} placeholder="Libellé"/></div><div className="pages-header"><h4>Pages</h4><div className="action-row"><button className="ghost" onClick={()=>setProfiles(rows=>rows.map((row,i)=>i===index?{...row,pages:[...row.pages,{id:'',name:'',default:false}]}:row))}><Plus/>Page</button><button className="danger" onClick={()=>setProfiles(rows=>rows.filter((_,i)=>i!==index))}><Trash2/></button></div></div>{profile.pages.map((page,pageIndex)=><div className="page-item" key={pageIndex}><label>ID de page<input value={page.id} onChange={e=>updatePage(index,pageIndex,'id',e.target.value)}/></label><label>Nom<input value={page.name} onChange={e=>updatePage(index,pageIndex,'name',e.target.value)}/></label><label><input type="checkbox" checked={page.default} onChange={e=>updatePage(index,pageIndex,'default',e.target.checked)}/> Page par défaut</label><button className="danger" onClick={()=>setProfiles(rows=>rows.map((row,i)=>i===index?{...row,pages:row.pages.filter((_,j)=>j!==pageIndex)}:row))}><Trash2/></button></div>)}</div>)}</div>:<Empty title="Aucun profil Facebook" text="Ajoutez les métadonnées des pages à administrer."/>}</section></>
}
export function PermissionsManagerPage(){
 const [rows,setRows]=useState<Permission[]>([]),[error,setError]=useState('')
 useEffect(()=>{api<Permission[]>('/permissions').then(setRows).catch(e=>setError(message(e)))},[])
 const grouped=useMemo(()=>({lecture:rows.filter(x=>!x.mutating&&!x.destructive),ecriture:rows.filter(x=>x.mutating&&!x.destructive),destructif:rows.filter(x=>x.destructive)}),[rows])
 return <><Header eyebrow="Moindre privilège" title="Permissions" text="Matrice synchronisée avec les permissions réellement acceptées par le serveur."/><Notice text={error} error/><section className="panel permission-grid">{Object.entries(grouped).flatMap(([group,items])=>items.map(p=><div key={p.name}><span><KeyRound/></span><div><code>{p.name}</code><p>{group}</p></div></div>))}</section></>
}
