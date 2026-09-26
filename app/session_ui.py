from app.shell_ui import SHELL_SCRIPT
from fastapi.responses import HTMLResponse, Response


SESSION_SCRIPT = r"""
(() => {
  const exportStamp = () => new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z');
  const exportName = value => String(value || 'Export').replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^[-._]+|[-._]+$/g, '').slice(0, 54) || 'Export';
  window.NCTExport = {
    stamp: exportStamp,
    download(prefix, extension, content, type = 'application/octet-stream') {
      const blob = content instanceof Blob ? content : new Blob([content], {type});
      const link = document.createElement('a');
      link.href = URL.createObjectURL(blob);
      link.download = `${exportName(prefix)}_${exportStamp()}.${extension}`;
      link.click();
      setTimeout(() => URL.revokeObjectURL(link.href), 0);
    },
    json(prefix, data) { this.download(prefix, 'json', JSON.stringify(data, null, 2), 'application/json'); },
    csv(prefix, rows) {
      const cell = value => `"${String(value ?? '').replace(/"/g, '""')}"`;
      this.download(prefix, 'csv', rows.map(row => row.map(cell).join(',')).join('\r\n') + '\r\n', 'text/csv;charset=utf-8');
    }
  };

  function installClearableInputs() {
    if (!document.getElementById('nct-clearable-style')) {
      const style = document.createElement('style');
      style.id = 'nct-clearable-style';
      style.textContent = '.nct-clearable-wrap{position:relative;display:block;min-width:0}.nct-clearable-wrap>input{width:100%!important;padding-right:36px!important}.nct-clearable-wrap>input[type="search"]::-webkit-search-cancel-button,.nct-clearable-wrap>input[type="search"]::-webkit-search-decoration{display:none!important;-webkit-appearance:none!important;appearance:none!important}.nct-input-clear{position:absolute!important;top:50%!important;right:6px!important;width:25px!important;height:25px!important;min-width:25px!important;margin:0!important;padding:0!important;border:0!important;border-radius:50%!important;background:transparent!important;color:#9eb0b8!important;font:700 18px/25px system-ui!important;transform:translateY(-50%)!important;cursor:pointer!important}.nct-input-clear:hover,.nct-input-clear:focus-visible{background:#1d3946!important;color:#edf6fb!important;outline:1px solid #57d6bf!important}.nct-input-clear[hidden]{display:none!important}.map-toolbar>.nct-clearable-wrap{flex:1 1 240px}.map-toolbar>.nct-clearable-wrap input{flex:none!important}';
      document.head.append(style);
    }
    const enhance = input => {
      if (!(input instanceof HTMLInputElement) || input.closest('.clearable,.nct-clearable-wrap,.network-search-control') || input.classList.contains('nct-note-search')) return;
      const parent = input.parentNode;
      if (!parent) return;
      const wrapper = document.createElement('span');
      wrapper.className = 'nct-clearable-wrap';
      parent.insertBefore(wrapper, input);
      wrapper.append(input);
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'nct-input-clear';
      button.textContent = '×';
      const label = input.getAttribute('aria-label') || input.labels?.[0]?.textContent?.trim() || 'field';
      button.setAttribute('aria-label', `Clear ${label}`);
      button.title = `Clear ${label}`;
      const sync = () => { button.hidden = !input.value; };
      input.addEventListener('input', sync);
      button.addEventListener('click', () => {
        input.value = '';
        input.dispatchEvent(new Event('input', {bubbles: true}));
        input.dispatchEvent(new Event('change', {bubbles: true}));
        input.focus();
      });
      wrapper.append(button);
      sync();
    };
    const scan = root => {
      if (root instanceof Element && root.matches('input[type="search"],input[data-nct-clearable="true"]')) enhance(root);
      root.querySelectorAll?.('input[type="search"],input[data-nct-clearable="true"]').forEach(enhance);
    };
    scan(document);
    new MutationObserver(changes => changes.forEach(change => change.addedNodes.forEach(scan))).observe(document.body, {childList: true, subtree: true});
  }

  async function installAccountControls() {
    const menu = document.getElementById('nct-account-menu');
    if (!menu || menu.dataset.ready === 'true') return;
    menu.dataset.ready = 'true';
    const status = document.getElementById('nct-account-status');
    const signIn = document.getElementById('nct-account-link');
    const accounts = document.getElementById('nct-accounts-link');
    const logout = document.getElementById('nct-sign-out');
    try {
      const response = await fetch('/api/auth/me', {credentials: 'same-origin'});
      if (!response.ok) {
        status.textContent = 'Not signed in';
        signIn.hidden = false;
        signIn.href = `/login?next=${encodeURIComponent(location.pathname + location.search)}`;
        return;
      }
      const data = await response.json();
      if (!data.authentication_enabled) {
        status.textContent = 'Local operator mode · accounts are disabled';
        installNotePanels({
          username: 'local-operator',
          display_name: 'Local operator',
          role: 'admin',
        });
        return;
      }
      if (!data.analyst) {
        status.textContent = 'Not signed in';
        return;
      }
      const analyst = data.analyst;
      status.textContent = `${analyst.display_name || analyst.username} · ${analyst.role}`;
      status.title = `Signed in as ${analyst.username}`;
      accounts.hidden = analyst.role !== 'admin';
      logout.hidden = false;
      logout.onclick = async () => {
        logout.disabled = true;
        await fetch('/api/auth/logout', {method: 'POST', credentials: 'same-origin'});
        location.href = '/login';
      };
      installNotePanels(analyst);
    } catch (_) {
      status.textContent = 'Account status is temporarily unavailable';
    }
  }

  function installNotePanels(analyst) {
    if (document.querySelector('.nct-note-panel')) return;
    const pageRoutes = {
      '/': 'device', '/operator': 'nmap', '/scans': 'nmap',
      '/device-config': 'device', '/device-analysis': 'device',
      '/analysis': 'analyze', '/hunting': 'hunt', '/reachability': 'reach',
      '/network-map': 'map'
    };
    const page = pageRoutes[location.pathname];
    if (!page) return;
    const pageLabel = {device:'Device', nmap:'Nmap', analyze:'Analyze', hunt:'Hunt', reach:'Reach', map:'Map'}[page];
    const canWrite = analyst.role !== 'viewer';
    let notes = [], personalSelected = null, sharedSelected = null;
    const expandedFolders = new Set();

    const style = document.createElement('style');
    style.textContent = `
      .nct-note-tab{position:fixed;top:48%;z-index:145;width:auto!important;margin:0!important;padding:10px 7px!important;border:1px solid #3c6072!important;background:#102b38!important;color:#eaf4f8!important;font:800 11px system-ui!important;letter-spacing:.04em;cursor:pointer;writing-mode:vertical-rl}
      .nct-note-tab.personal{left:var(--nct-sidebar-width,278px);border-radius:0 8px 8px 0!important}.nct-note-tab.shared{right:0;border-radius:8px 0 0 8px!important}
      .nct-note-tab .count{margin-top:5px;color:#57d6bf}.nct-note-panel{position:fixed;top:118px;bottom:10px;z-index:144;display:flex;width:min(420px,calc(100vw - 24px));flex-direction:column;border:1px solid #315367;background:#081720f7;color:#eaf4f8;box-shadow:0 18px 55px #000b;font:13px system-ui;transition:transform .18s ease}
      .nct-note-panel.personal{left:var(--nct-sidebar-width,278px);border-radius:0 12px 12px 0;transform:translateX(-102%)}.nct-note-panel.shared{right:0;border-radius:12px 0 0 12px;transform:translateX(102%)}.nct-note-panel.open{transform:none}
      .nct-note-head{display:flex;align-items:flex-start;justify-content:space-between;gap:10px;padding:13px 14px;border-bottom:1px solid #315367;background:#0d2633}.nct-note-head strong{display:block;font-size:15px}.nct-note-head small{display:block;margin-top:2px;color:#a9c3cf}.nct-note-head button{width:auto!important;margin:0!important;padding:4px 8px!important;background:#091722!important;color:#dcecf2!important;border:1px solid #3c6072!important}
      .nct-note-search{margin:10px 12px 6px!important;width:calc(100% - 24px)!important;padding:8px!important;border:1px solid #315367!important;border-radius:6px!important;background:#07121a!important;color:#eaf4f8!important;font:13px system-ui!important}.nct-note-tools{display:flex;gap:6px;padding:0 12px 9px}.nct-note-tools button,.nct-note-actions button{width:auto!important;margin:0!important;padding:6px 8px!important;border:1px solid #3c6072!important;border-radius:6px!important;background:#102b38!important;color:#eaf4f8!important;font:750 11px system-ui!important;cursor:pointer}.nct-note-tools button:disabled,.nct-note-actions button:disabled{opacity:.45;cursor:not-allowed}
      .nct-note-tree{flex:0 0 34%;min-height:105px;overflow:auto;padding:4px 8px 9px;border-top:1px solid #1d3542;border-bottom:1px solid #315367}.nct-note-row{display:flex;align-items:center;gap:4px;width:100%;min-height:28px;border-radius:5px;color:#cce0e7}.nct-note-row.selected{background:#174052;color:#fff}.nct-note-row.shared-item{border-left:2px solid #b88ae6}.nct-note-fold{flex:0 0 20px;width:20px!important;margin:0!important;padding:2px!important;border:0!important;background:transparent!important;color:#9eb7c2!important}.nct-note-select{min-width:0;flex:1;width:auto!important;margin:0!important;padding:5px 4px!important;border:0!important;background:transparent!important;color:inherit!important;text-align:left;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font:650 12px system-ui!important}.nct-note-owner{padding-right:5px;color:#b88ae6;font-size:9px}.nct-note-empty{padding:18px 10px;color:#8eaab6;text-align:center}
      .nct-note-editor{display:flex;min-height:0;flex:1;flex-direction:column;gap:8px;padding:11px 12px;overflow:auto}.nct-note-editor[hidden]{display:none}.nct-note-meta{display:flex;align-items:center;gap:6px;flex-wrap:wrap;color:#9eb7c2;font-size:10px}.nct-note-badge{padding:2px 6px;border:1px solid #315367;border-radius:999px}.nct-note-badge.shared{border-color:#9a70c0;color:#d7b8f4}.nct-note-editor label{display:grid;gap:4px;color:#b9d5df;font-size:11px;font-weight:750}.nct-note-editor input,.nct-note-editor select,.nct-note-editor textarea{width:100%!important;margin:0!important;padding:8px!important;border:1px solid #315367!important;border-radius:6px!important;background:#07121a!important;color:#eaf4f8!important;font:13px system-ui!important}.nct-note-editor textarea{min-height:170px;flex:1;resize:vertical;font-family:ui-monospace,SFMono-Regular,Consolas,monospace!important;line-height:1.45}.nct-note-context{padding:7px;border:1px dashed #315367;border-radius:6px;color:#9eb7c2;font-size:11px}.nct-note-actions{display:flex;gap:6px;flex-wrap:wrap}.nct-note-actions .primary{background:#57d6bf!important;color:#06201d!important}.nct-note-actions .danger{border-color:#8e4a55!important;color:#ffb0b9!important}.nct-note-status{min-height:17px;color:#9eb7c2;font-size:11px}.nct-note-status.bad{color:#ff9f9f}.nct-note-status.good{color:#77e3b5}
      html[data-nct-theme^="dcc_"] .nct-note-panel{border:2px solid #8a7046!important;background:linear-gradient(100deg,#0c1215 0 18px,#172226 19px 22px,#11191c 23px 100%)!important;box-shadow:0 20px 60px #000d,inset 5px 0 #c7a45b22!important}
      html[data-nct-theme^="dcc_"] .nct-note-head{position:relative;padding-bottom:30px;border-bottom:1px solid #8a7046!important;background:linear-gradient(90deg,#19282b,#10191c)!important;color:#ead9ad!important}
      html[data-nct-theme^="dcc_"] .nct-note-head::before{content:"FIELD EDITION";position:absolute;left:14px;bottom:9px;color:#c7a45b;font:800 8px/1 ui-monospace,monospace;letter-spacing:.18em}
      html[data-nct-theme^="dcc_"] .nct-note-tab{border-color:#8a7046!important;background:#172226!important;color:#ead9ad!important;box-shadow:0 0 16px #c7a45b22!important}
      html[data-nct-theme^="dcc_"] .nct-note-editor textarea{background:repeating-linear-gradient(180deg,#0d1518 0 27px,#8a704629 28px)!important;color:#f3e6c2!important;border-color:#8a7046!important;line-height:28px!important}
      html[data-nct-theme^="dcc_"] .nct-note-tree{border-color:#8a7046!important}html[data-nct-theme^="dcc_"] .nct-note-row.selected{background:#8a704633!important;color:#f3e6c2!important}
      @media(max-width:700px){.nct-note-panel{top:102px;bottom:4px}.nct-note-tab{top:auto;bottom:12px;writing-mode:horizontal-tb}.nct-note-tab.personal,body.nct-nav-closed .nct-note-tab.personal{left:8px;border-radius:7px!important}.nct-note-panel.personal,body.nct-nav-closed .nct-note-panel.personal{left:0}.nct-note-tab.shared{right:8px;border-radius:7px!important}}
    `;
    document.head.append(style);

    function panelMarkup(side) {
      const personal = side === 'personal';
      const title = personal ? 'Personal notes' : `${pageLabel} shared notes`;
      const subtitle = personal ? 'Private to your analyst account' : `Team notes published to ${pageLabel}`;
      return `<div class="nct-note-head"><div><strong>${title}</strong><small>${subtitle}</small></div><button type="button" data-note-close>Close</button></div>
        <input class="nct-note-search" type="search" placeholder="Search ${personal?'my':'shared'} notes" aria-label="Search notes">
        ${personal?`<div class="nct-note-tools"><button type="button" data-new-note ${canWrite?'':'disabled'}>+ Note</button><button type="button" data-new-folder ${canWrite?'':'disabled'}>+ Folder</button><button type="button" data-reload>Refresh</button></div>`:''}
        <div class="nct-note-tree"></div><div class="nct-note-editor" hidden></div>`;
    }
    function makeSide(side) {
      const tab = document.createElement('button');
      tab.type='button';tab.className=`nct-note-tab ${side}`;
      tab.innerHTML=`<span class="nct-note-tab-label">${side==='personal'?'Personal notes':`${pageLabel} shared`}</span> <span class="count"></span>`;
      const panel=document.createElement('aside');panel.className=`nct-note-panel ${side}`;panel.setAttribute('aria-label',side==='personal'?'Personal investigation notes':`${pageLabel} shared investigation notes`);panel.innerHTML=panelMarkup(side);
      document.body.append(tab,panel);
      tab.onclick=()=>togglePanel(side,!panel.classList.contains('open'));
      panel.querySelector('[data-note-close]').onclick=()=>togglePanel(side,false);
      panel.querySelector('.nct-note-search').oninput=()=>renderTree(side);
      if(side==='personal'){
        panel.querySelector('[data-new-note]').onclick=()=>createItem('note');
        panel.querySelector('[data-new-folder]').onclick=()=>createItem('folder');
        panel.querySelector('[data-reload]').onclick=()=>loadNotes(personalSelected);
      }
      return {tab,panel};
    }
    const personalSide=makeSide('personal'),sharedSide=makeSide('shared');
    function applyCookbookIdentity(preset=document.documentElement.dataset.nctTheme||''){const enabled=String(preset).startsWith('dcc_'),personalTitle=personalSide.panel.querySelector('.nct-note-head strong'),personalSub=personalSide.panel.querySelector('.nct-note-head small'),sharedTitle=sharedSide.panel.querySelector('.nct-note-head strong'),sharedSub=sharedSide.panel.querySelector('.nct-note-head small'),personalSearch=personalSide.panel.querySelector('.nct-note-search'),sharedSearch=sharedSide.panel.querySelector('.nct-note-search');personalSide.tab.querySelector('.nct-note-tab-label').textContent=enabled?'Cookbook':'Personal notes';sharedSide.tab.querySelector('.nct-note-tab-label').textContent=enabled?`${pageLabel} cookbook`:`${pageLabel} shared`;personalTitle.textContent=enabled?"Dungeon Anarchist’s Cookbook":'Personal notes';personalSub.textContent=enabled?'Private field entries for this crawler':'Private to your analyst account';sharedTitle.textContent=enabled?`${pageLabel} shared cookbook`:`${pageLabel} shared notes`;sharedSub.textContent=enabled?`Team field entries published to ${pageLabel}`:`Team notes published to ${pageLabel}`;personalSearch.placeholder=enabled?'Search my cookbook':'Search my notes';sharedSearch.placeholder=enabled?'Search shared cookbook':'Search shared notes';personalSide.panel.setAttribute('aria-label',enabled?"Personal Dungeon Anarchist’s Cookbook":'Personal investigation notes');sharedSide.panel.setAttribute('aria-label',enabled?`${pageLabel} shared cookbook`:`${pageLabel} shared investigation notes`);const addNote=personalSide.panel.querySelector('[data-new-note]'),addFolder=personalSide.panel.querySelector('[data-new-folder]');if(addNote)addNote.textContent=enabled?'+ Entry':'+ Note';if(addFolder)addFolder.textContent=enabled?'+ Chapter':'+ Folder';}
    applyCookbookIdentity();window.addEventListener('nct-theme-change',event=>applyCookbookIdentity(event.detail?.preset));

    function togglePanel(side,open){
      const target=side==='personal'?personalSide:sharedSide;
      const other=side==='personal'?sharedSide:personalSide;
      if(open){
        other.panel.classList.remove('open');
        other.tab.setAttribute('aria-expanded','false');
        localStorage.setItem(`nct-${side==='personal'?'shared':'personal'}-notes-open`,'0');
      }
      target.panel.classList.toggle('open',open);target.tab.setAttribute('aria-expanded',String(open));
      localStorage.setItem(`nct-${side}-notes-open`,open?'1':'0');
      if(open&&side==='shared'&&page==='map'){
        const workspace=document.querySelector('.workspace'),details=document.getElementById('toggleDetails');
        if(workspace&&!workspace.classList.contains('details-empty')&&details?.getAttribute('aria-pressed')==='false')details.click();
      }
    }
    const ownNotes=()=>notes.filter(item=>item.owner===analyst.username);
    const sharedNotes=()=>notes.filter(item=>item.visibility==='shared'&&item.shared_page===page);
    const itemById=id=>notes.find(item=>item.note_id===id);
    const childrenOf=(items,parent)=>items.filter(item=>(item.parent_id||null)===(parent||null));
    function descendants(id){const found=new Set();const walk=parent=>childrenOf(ownNotes(),parent).forEach(item=>{found.add(item.note_id);walk(item.note_id)});walk(id);return found}
    function renderTree(side){
      const holder=(side==='personal'?personalSide:sharedSide).panel.querySelector('.nct-note-tree'),source=side==='personal'?ownNotes():sharedNotes(),selected=side==='personal'?personalSelected:sharedSelected,query=(side==='personal'?personalSide:sharedSide).panel.querySelector('.nct-note-search').value.trim().toLowerCase();holder.replaceChildren();
      if(!source.length){const empty=document.createElement('div');empty.className='nct-note-empty';empty.textContent=side==='personal'?'No personal notes yet.':'No notes have been shared to this page.';holder.append(empty);return}
      const matching=query?new Set(source.filter(item=>`${item.title} ${item.content}`.toLowerCase().includes(query)).map(item=>item.note_id)):null;
      const roots=source.filter(item=>!item.parent_id||!source.some(parent=>parent.note_id===item.parent_id));
      const append=(item,depth)=>{
        const childItems=childrenOf(source,item.note_id),show=!matching||matching.has(item.note_id)||childItems.some(child=>matching.has(child.note_id));if(!show)return;
        const row=document.createElement('div');row.className=`nct-note-row${selected===item.note_id?' selected':''}${item.visibility==='shared'?' shared-item':''}`;row.style.paddingLeft=`${Math.min(depth,8)*13}px`;
        const fold=document.createElement('button');fold.type='button';fold.className='nct-note-fold';fold.textContent=item.kind==='folder'?(expandedFolders.has(item.note_id)?'▾':'▸'):'·';fold.disabled=item.kind!=='folder';fold.onclick=event=>{event.stopPropagation();if(expandedFolders.has(item.note_id))expandedFolders.delete(item.note_id);else expandedFolders.add(item.note_id);renderTree(side)};
        const choose=document.createElement('button');choose.type='button';choose.className='nct-note-select';choose.textContent=`${item.kind==='folder'?'Folder · ':'Note · '}${item.title}`;choose.onclick=()=>selectItem(side,item.note_id);
        row.append(fold,choose);if(side==='shared'){const owner=document.createElement('span');owner.className='nct-note-owner';owner.textContent=item.owner;row.append(owner)}holder.append(row);
        if(item.kind==='folder'&&(expandedFolders.has(item.note_id)||query))childItems.forEach(child=>append(child,depth+1));
      };roots.forEach(item=>append(item,0));
    }
    function contextText(item){const context=item.context||{};return context.source_url?`Linked to ${context.source_label||context.source_page||'NCT'} · ${context.source_url}`:'Not linked to a specific record or view.'}
    function selectItem(side,id){if(side==='personal')personalSelected=id;else sharedSelected=id;renderTree(side);renderEditor(side,itemById(id))}
    function renderEditor(side,item){const editor=(side==='personal'?personalSide:sharedSide).panel.querySelector('.nct-note-editor');if(!item){editor.hidden=true;editor.replaceChildren();return}editor.hidden=false;const writable=side==='personal'&&item.writable&&canWrite;
      if(!writable){const sharedBy=document.documentElement.dataset.nctTheme?.startsWith('dcc_')?`NEW CODEX ENTRY: Shared by Crawler ${escapeHtml(item.owner)}`:`Shared by ${escapeHtml(item.owner)}`;editor.innerHTML=`<div class="nct-note-meta"><span class="nct-note-badge shared">${sharedBy}</span><span>Updated ${escapeHtml(item.updated_at)}</span></div><label>Title<input data-title readonly></label>${item.kind==='note'?'<label style="flex:1">Note<textarea data-content readonly></textarea></label>':''}<div class="nct-note-context"></div><div class="nct-note-actions"><button type="button" data-export>Download Markdown</button></div>`;editor.querySelector('[data-title]').value=item.title;if(item.kind==='note')editor.querySelector('[data-content]').value=item.content||'';editor.querySelector('.nct-note-context').textContent=contextText(item);editor.querySelector('[data-export]').onclick=()=>exportItem(item);return}
      const folders=ownNotes().filter(folder=>folder.kind==='folder'&&folder.note_id!==item.note_id&&!descendants(item.note_id).has(folder.note_id));
      editor.innerHTML=`<div class="nct-note-meta"><span class="nct-note-badge ${item.visibility==='shared'?'shared':''}">${item.visibility==='shared'?`Shared on ${pageName(item.shared_page)}`:'Personal'}</span><span>Version ${item.version}</span></div><label>Title<input data-title maxlength="140"></label><label>Location<select data-parent><option value="">Top level</option>${folders.map(folder=>`<option value="${escapeHtml(folder.note_id)}">${escapeHtml(folder.title)}</option>`).join('')}</select></label>${item.kind==='note'?'<label style="flex:1">Note<textarea data-content maxlength="250000" placeholder="Record observations, leads, questions, and conclusions…"></textarea></label>':''}<div class="nct-note-context"></div><div class="nct-note-actions"><button class="primary" type="button" data-save>Save</button><button type="button" data-link>Link current view</button><button type="button" data-export>Download Markdown</button><button type="button" data-share>${item.visibility==='shared'&&item.shared_page===page?'Unshare':`Share on ${pageLabel}`}</button><button class="danger" type="button" data-delete>Delete</button></div><div class="nct-note-status" role="status"></div>`;
      editor.querySelector('[data-title]').value=item.title;editor.querySelector('[data-parent]').value=item.parent_id||'';if(item.kind==='note')editor.querySelector('[data-content]').value=item.content||'';editor.querySelector('.nct-note-context').textContent=contextText(item);
      editor.querySelector('[data-save]').onclick=()=>saveItem(item);editor.querySelector('[data-link]').onclick=()=>linkItem(item);editor.querySelector('[data-export]').onclick=()=>exportItem(item);editor.querySelector('[data-share]').onclick=()=>toggleShare(item);editor.querySelector('[data-delete]').onclick=()=>deleteItem(item);
    }
    function pageName(value){return {device:'Device',nmap:'Nmap',analyze:'Analyze',hunt:'Hunt',reach:'Reach',map:'Map'}[value]||value||'NCT'}
    function escapeHtml(value){return String(value??'').replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]))}
    async function api(url,options){const response=await fetch(url,{credentials:'same-origin',...options}),data=await response.json();if(!response.ok)throw new Error(data.detail||'The note change could not be completed');return data}
    function status(message,kind=''){const node=personalSide.panel.querySelector('.nct-note-status');if(node){node.textContent=message;node.className=`nct-note-status ${kind}`}}
    async function loadNotes(selectId=null){try{const data=await api(`/api/workspaces/notes?page=${encodeURIComponent(page)}`);notes=data.notes||[];if(selectId&&itemById(selectId))personalSelected=selectId;if(personalSelected&&!itemById(personalSelected))personalSelected=null;if(sharedSelected&&!itemById(sharedSelected))sharedSelected=null;personalSide.tab.querySelector('.count').textContent=ownNotes().length;sharedSide.tab.querySelector('.count').textContent=sharedNotes().length;renderTree('personal');renderTree('shared');renderEditor('personal',itemById(personalSelected));renderEditor('shared',itemById(sharedSelected))}catch(error){personalSide.tab.title=error.message;sharedSide.tab.title=error.message}}
    function preferredParent(){const selected=itemById(personalSelected);return selected?.kind==='folder'?selected.note_id:selected?.parent_id||null}
    async function createItem(kind){try{const created=await api('/api/workspaces/notes',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({title:kind==='folder'?'New folder':'New note',kind,content:'',context:{},parent_id:preferredParent()})});if(created.parent_id)expandedFolders.add(created.parent_id);await loadNotes(created.note_id);personalSide.panel.querySelector('[data-title]')?.select();status(`${kind==='folder'?'Folder':'Note'} created.`,'good')}catch(error){status(error.message,'bad')}}
    async function saveItem(item,context=item.context||{}){const editor=personalSide.panel.querySelector('.nct-note-editor'),payload={note_id:item.note_id,expected_version:item.version,title:editor.querySelector('[data-title]').value.trim(),kind:item.kind,content:item.kind==='note'?editor.querySelector('[data-content]').value:'',context,parent_id:editor.querySelector('[data-parent]').value||null};status('Saving…');try{const saved=await api('/api/workspaces/notes',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});await loadNotes(saved.note_id);status('Saved.','good')}catch(error){status(error.message,'bad')}}
    async function linkItem(item){const linked={...(item.context||{}),source_page:page,source_label:document.title,source_url:location.pathname+location.search,linked_at:new Date().toISOString()};await saveItem(item,linked)}
    function exportItem(item){location.href=`/api/workspaces/notes/${encodeURIComponent(item.note_id)}/export?page=${encodeURIComponent(page)}`}
    async function toggleShare(item){const sharing=!(item.visibility==='shared'&&item.shared_page===page),verb=sharing?`share ${item.kind==='folder'?'this folder and its contents':'this note'} on ${pageLabel}`:'return this item to personal-only';if(!confirm(`Are you sure you want to ${verb}?`))return;status(sharing?'Sharing…':'Unsharing…');try{const saved=await api(`/api/workspaces/notes/${encodeURIComponent(item.note_id)}/share`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({shared:sharing,page:sharing?page:null,expected_version:item.version})});await loadNotes(saved.note_id);status(sharing?`Shared on ${pageLabel}.`:'Returned to personal notes.','good')}catch(error){status(error.message,'bad')}}
    async function deleteItem(item){if(!confirm(`Delete ${item.title}${item.kind==='folder'?' and everything inside it':''}? This cannot be undone.`))return;status('Deleting…');try{await api(`/api/workspaces/notes/${encodeURIComponent(item.note_id)}?expected_version=${item.version}`,{method:'DELETE'});personalSelected=null;await loadNotes();status('Deleted.','good')}catch(error){status(error.message,'bad')}}
    if(localStorage.getItem('nct-personal-notes-open')==='1')togglePanel('personal',true);if(localStorage.getItem('nct-shared-notes-open')==='1')togglePanel('shared',true);loadNotes();
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => { installClearableInputs(); installAccountControls(); }, {once: true});
  } else {
    installClearableInputs();
    installAccountControls();
  }
})();
"""


def session_script() -> Response:
    return Response(
        SHELL_SCRIPT + "\n" + SESSION_SCRIPT,
        media_type="application/javascript",
        headers={"Cache-Control": "no-store"},
    )


def analyst_admin_page() -> HTMLResponse:
    return HTMLResponse(
        r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>NCT · Analyst accounts</title>
<style>:root{color-scheme:dark;--bg:#07121a;--panel:#0d1c26;--line:#315367;--text:#eaf4f8;--muted:#a9c3cf;--accent:#57d6bf}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:16px system-ui}header{position:sticky;top:0;z-index:100;padding:10px 24px;border-bottom:1px solid var(--line);background:#07121af5}.sr-only{position:absolute;width:1px;height:1px;margin:-1px;overflow:hidden;clip:rect(0,0,0,0)}.nct-brand{display:flex;width:max-content;flex-direction:column;align-items:center;margin:0 auto;line-height:1}.nct-brand>strong{padding-left:.24em;font-size:40px;letter-spacing:.24em}.nct-brand span{margin-top:3px;padding-top:3px;border-top:1px solid var(--accent);color:var(--muted);font-size:9px;font-weight:650;letter-spacing:.09em;text-transform:uppercase}.nct-brand span b{color:var(--accent)}.nav{display:flex;justify-content:center;gap:10px;margin-top:8px}.nav a{padding:6px 12px;border:1px solid var(--line);border-radius:7px;background:#102b38;color:var(--text);font-weight:750;text-decoration:none}.nav a.active{background:var(--accent);color:#06201d}main{width:min(1120px,calc(100% - 32px));margin:22px auto}.panel{padding:22px;border:1px solid var(--line);border-radius:12px;background:var(--panel)}h2{margin-top:0}.hint,.status{color:var(--muted)}form{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:18px}label{display:grid;gap:6px;font-weight:750}input,select,button{padding:11px;border:1px solid #3c6072;border-radius:7px;background:#091722;color:inherit;font:inherit}button{align-self:end;background:var(--accent);color:#06201d;font-weight:850;cursor:pointer}.wide{grid-column:1/-1}.table-wrap{margin-top:20px;overflow:auto}table{width:100%;border-collapse:collapse}th,td{padding:10px;border-bottom:1px solid #263f4d;text-align:left}th{color:#b9d5df}.bad{color:#ff9f9f}.good{color:#77e3b5}.account-actions{display:flex;gap:6px;flex-wrap:wrap}.account-actions button{padding:6px 8px;background:#102b38;color:var(--text);font-size:12px}.account-actions .danger{border-color:#8e4a55;color:#ffb0b9}.disabled-account{opacity:.58}details{margin-top:22px}dialog{width:min(480px,calc(100% - 32px));padding:22px;border:1px solid var(--line);border-radius:12px;background:var(--panel);color:var(--text)}dialog::backdrop{background:#000b}dialog form{grid-template-columns:1fr}.dialog-actions{display:flex;gap:8px;justify-content:flex-end}.dialog-actions button{width:auto}@media(max-width:760px){form{grid-template-columns:1fr}.wide{grid-column:auto}}</style><script src="/assets/nct-session.js"></script></head><body>
<header><div class="nct-brand" aria-label="NCT, Network Characterization Tool"><strong>NCT</strong><span><b>N</b>etwork <b>C</b>haracterization <b>T</b>ool</span></div></header>
<main><section class="panel"><h2>Analyst accounts</h2><p class="hint">Administrators create named accounts here. Passwords are stored as hardened hashes and are never displayed again.</p>
<form id="createUser"><label>Username<input id="username" required minlength="2" maxlength="64" autocomplete="off"></label><label>Display name<input id="displayName" required maxlength="100" autocomplete="off"></label><label>Role<select id="role"><option value="analyst">Analyst</option><option value="viewer">Viewer</option><option value="admin">Administrator</option></select></label><label>Initial password<input id="password" type="password" required minlength="12" maxlength="256" autocomplete="new-password"></label><button class="wide" type="submit">Create account</button></form><p id="status" class="status" role="status"></p>
<div class="table-wrap"><table><thead><tr><th>Account</th><th>Display name</th><th>Role</th><th>Status</th><th>Created</th><th>Created by</th><th>Actions</th></tr></thead><tbody id="accounts"></tbody></table></div>
<details><summary>Account audit history</summary><div class="table-wrap"><table><thead><tr><th>Time</th><th>Account</th><th>Action</th><th>Administrator</th></tr></thead><tbody id="audit"></tbody></table></div></details></section></main>
<dialog id="passwordDialog"><h2>Reset account password</h2><p id="passwordTarget" class="hint"></p><form id="resetPassword"><input id="resetUsername" type="hidden"><label>New password<input id="newPassword" type="password" required minlength="12" maxlength="256" autocomplete="new-password"></label><div class="dialog-actions"><button id="cancelReset" type="button">Cancel</button><button type="submit">Reset password</button></div><p id="resetStatus" class="status" role="status"></p></form></dialog>
<script>
const esc=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(url,options){const response=await fetch(url,options),data=await response.json();if(!response.ok)throw new Error(data.detail||'The account change could not be completed');return data}
async function loadAccounts(){const items=await api('/api/auth/users');accounts.innerHTML=items.map(item=>`<tr class="${item.disabled?'disabled-account':''}"><td><strong>${esc(item.username)}</strong></td><td>${esc(item.display_name)}</td><td>${esc(item.role)}</td><td>${item.disabled?'Disabled':'Active'}</td><td>${esc(item.created_at)}</td><td>${esc(item.created_by)}</td><td><div class="account-actions"><button type="button" data-reset="${esc(item.username)}">Reset password</button><button type="button" class="${item.disabled?'':'danger'}" data-state="${esc(item.username)}" data-disabled="${item.disabled?'false':'true'}">${item.disabled?'Enable':'Disable'}</button></div></td></tr>`).join('')}
async function loadAudit(){const items=await api('/api/auth/audit?limit=200');audit.innerHTML=items.map(item=>`<tr><td>${esc(item.changed_at)}</td><td>${esc(item.username)}</td><td>${esc(item.action.replaceAll('_',' '))}</td><td>${esc(item.actor)}</td></tr>`).join('')}
createUser.onsubmit=async event=>{event.preventDefault();status.textContent='Creating account…';status.className='status';try{const data=await api('/api/auth/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:username.value.trim(),display_name:displayName.value.trim(),role:role.value,password:password.value})});createUser.reset();status.textContent=`Created ${data.username}.`;status.className='status good';await Promise.all([loadAccounts(),loadAudit()])}catch(error){status.textContent=error.message;status.className='status bad'}};
accounts.onclick=async event=>{const reset=event.target.closest('[data-reset]'),stateButton=event.target.closest('[data-state]');if(reset){resetUsername.value=reset.dataset.reset;passwordTarget.textContent=`Set a new password for ${reset.dataset.reset}. All of that account's current sessions will be signed out.`;newPassword.value='';resetStatus.textContent='';passwordDialog.showModal();newPassword.focus();return}if(!stateButton)return;const disabled=stateButton.dataset.disabled==='true',username=stateButton.dataset.state;if(!confirm(`${disabled?'Disable':'Enable'} ${username}?${disabled?' All current sessions will be signed out.':''}`))return;try{await api(`/api/auth/users/${encodeURIComponent(username)}/state`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({disabled})});status.textContent=`${username} is now ${disabled?'disabled':'active'}.`;status.className='status good';await Promise.all([loadAccounts(),loadAudit()])}catch(error){status.textContent=error.message;status.className='status bad'}};
cancelReset.onclick=()=>passwordDialog.close();resetPassword.onsubmit=async event=>{event.preventDefault();resetStatus.textContent='Resetting password…';try{await api(`/api/auth/users/${encodeURIComponent(resetUsername.value)}/password`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:newPassword.value})});passwordDialog.close();status.textContent=`Password reset for ${resetUsername.value}; existing sessions were signed out.`;status.className='status good';await loadAudit()}catch(error){resetStatus.textContent=error.message;resetStatus.className='status bad'}};
Promise.all([loadAccounts(),loadAudit()]).catch(error=>{status.textContent=error.message;status.className='status bad'});
</script></body></html>'''
    )
