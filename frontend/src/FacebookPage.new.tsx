// This is the reformatted FacebookPage with long-lived token management
// Will be minified and replaced in App.tsx

function FacebookPage(){
  const [profiles,setProfiles]=useState<FacebookProfile[]>([]);
  const [notice,setNotice]=useState('');
  const [busy,setBusy]=useState(false);
  const [shortToken,setShortToken]=useState('');
  const [tokenStatus,setTokenStatus]=useState<{has_token:boolean;status:string;expiry?:string;days_remaining?:number}|null>(null);
  const [tokenBusy,setTokenBusy]=useState(false);
  
  const load=()=>api<{accounts:FacebookProfile[]}>('/facebook/config').then(r=>setProfiles(r.accounts??[])).catch(x=>setNotice(String(x)));
  const loadTokenStatus=()=>api<typeof tokenStatus>('/facebook/token-status').then(setTokenStatus).catch(x=>console.error(x));
  
  useEffect(()=>{void load();void loadTokenStatus()},[]);
  
  async function exchangeToken(){
    if(!shortToken.trim()){
      setNotice('Veuillez entrer un token court durée');
      return;
    }
    setTokenBusy(true);
    try{
      const r=await api<{success:boolean;status:typeof tokenStatus}>('/facebook/exchange-token',{method:'POST',body:JSON.stringify({short_lived_token:shortToken})});
      if(r.success){
        setShortToken('');
        setTokenStatus(r.status);
        setNotice('Token échangé avec succès! Valide jusqu\'au '+r.status?.expiry);
      }
    }catch(error){
      setNotice(error instanceof Error?error.message:String(error))
    }finally{
      setTokenBusy(false)
    }
  }
  
  async function clearToken(){
    if(!confirm('Êtes-vous sûr de vouloir supprimer le token longue durée?'))return;
    setTokenBusy(true);
    try{
      await api('/facebook/clear-token',{method:'POST'});
      setTokenStatus(null);
      setNotice('Token supprimé.');
      void loadTokenStatus();
    }catch(error){
      setNotice(error instanceof Error?error.message:String(error))
    }finally{
      setTokenBusy(false)
    }
  }
  
  function addProfile(){
    setProfiles(prev=>[...prev,{id:`fb-${Date.now()}`,label:'',app_id:'',app_secret:'',user_access_token:'',page_access_token:'',default_page_id:'',pages:[]}])
  }
  
  function addPage(profileIndex:number){
    setProfiles(prev=>prev.map((profile,index)=>index===profileIndex?{...profile,pages:[...profile.pages,{id:'',name:'',access_token:'',default:false}]}:profile))
  }
  
  function updateProfile(index:number,field:keyof FacebookProfile,value:string){
    setProfiles(prev=>prev.map((profile,i)=>i===index?{...profile,[field]:value}:profile))
  }
  
  function updatePage(profileIndex:number,pageIndex:number,field:'id'|'name'|'access_token'|'default',value:string|boolean){
    setProfiles(prev=>prev.map((profile,i)=>i!==profileIndex?profile:{...profile,pages:profile.pages.map((page,j)=>j!==pageIndex?page:{...page,[field]:value})}))
  }
  
  async function save(){
    setBusy(true);
    try{
      await api('/facebook/config',{method:'POST',body:JSON.stringify({accounts:profiles})});
      setNotice('Configuration Facebook enregistrée.')
    }catch(error){
      setNotice(error instanceof Error?error.message:String(error))
    }finally{
      setBusy(false)
    }
  }
  
  const tokenStatusUI=tokenStatus?(<div className="token-status"><span className={`pill ${tokenStatus.status==='valid'?'ok':tokenStatus.status.startsWith('expiring')?'warn':'error'}`}>{tokenStatus.status==='valid'?'Valide':tokenStatus.status==='no_token'?'Non configuré':'En attente'}</span>{tokenStatus.expiry&&<small>Expire le {new Date(tokenStatus.expiry).toLocaleDateString('fr-FR')}</small>}{tokenStatus.days_remaining!==undefined&&<small>{tokenStatus.days_remaining} jours restants</small>}</div>):null;
  
  return <>
    <Header eyebrow="Réseaux sociaux" title="Facebook" text="Gérez plusieurs comptes et pages Facebook depuis le même panneau d'administration." action={<button className="primary" onClick={save} disabled={busy}>{busy?'Enregistrement…':'Sauvegarder'}</button>}/>
    {notice&&<div className="notice">{notice}</div>}
    <section className="panel">
      <div className="panel-title"><div><h3>Authentification utilisateur</h3><p>Utilisez un token court-durée de Facebook pour obtenir un token long-durée (60 jours) qui sera utilisé pour récupérer les tokens de page automatiquement.</p></div></div>
      <div className="token-exchange">
        <label>Token court-durée (de Facebook)<input type="password" value={shortToken} onChange={e=>setShortToken(e.target.value)} placeholder="Copiez depuis le développeur Facebook" required/></label>
        <button className="primary" onClick={exchangeToken} disabled={tokenBusy||!shortToken.trim()}>{tokenBusy?'Échange en cours…':'Échanger le token'}</button>
        {tokenStatus&&<button onClick={clearToken} disabled={tokenBusy}>Effacer le token</button>}
      </div>
      {tokenStatusUI}
    </section>
    <section className="panel">
      <div className="toolbar">
        <button className="primary" onClick={addProfile}><Plus/>Ajouter un profil</button>
      </div>
      {profiles.length===0?<Empty title="Aucun profil Facebook" text="Ajoutez un compte pour stocker les tokens et pages."/>:<div className="profile-list">{profiles.map((profile,index)=><div key={profile.id} className="profile"><div className="profile-header"><input type="text" value={profile.label} onChange={e=>updateProfile(index,'label',e.target.value)} placeholder="Label du profil"/></div><div className="profile-fields"><label>App ID<input type="text" value={profile.app_id} onChange={e=>updateProfile(index,'app_id',e.target.value)} placeholder="123456789"/></label><label>App Secret<input type="password" value={profile.app_secret} onChange={e=>updateProfile(index,'app_secret',e.target.value)} placeholder="secret"/></label><label>User Access Token<input type="password" value={profile.user_access_token} onChange={e=>updateProfile(index,'user_access_token',e.target.value)} placeholder="token"/></label><label>Page Access Token<input type="password" value={profile.page_access_token} onChange={e=>updateProfile(index,'page_access_token',e.target.value)} placeholder="token"/></label><label>Page ID par défaut<input type="text" value={profile.default_page_id||''} onChange={e=>updateProfile(index,'default_page_id',e.target.value)} placeholder="123456789"/></label></div><div><div className="pages-list"><div className="pages-header"><h4>Pages</h4><button className="ghost" onClick={()=>addPage(index)}><Plus/>Ajouter une page</button></div>{profile.pages.map((page,pageIndex)=><div key={pageIndex} className="page-item"><label>Page ID<input type="text" value={page.id} onChange={e=>updatePage(index,pageIndex,'id',e.target.value)} placeholder="123456789"/></label><label>Nom de la page<input type="text" value={page.name} onChange={e=>updatePage(index,pageIndex,'name',e.target.value)} placeholder="Ma page"/></label><label>Access token de page<input type="password" value={page.access_token} onChange={e=>updatePage(index,pageIndex,'access_token',e.target.value)} placeholder="token"/></label><label style={{display:'flex',alignItems:'center',gap:8}}><input type="checkbox" checked={page.default} onChange={e=>updatePage(index,pageIndex,'default',e.target.checked)} /> Page par défaut</label></div>)}</div></div></div>)}</div>}
    </section>
  </>
}
