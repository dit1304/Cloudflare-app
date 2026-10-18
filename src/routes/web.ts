// Zero TempMail — web UI (paper & ink edition)
// Disajikan langsung oleh Worker di route "/".

export const WEB_HTML = `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Zero TempMail</title>
<style>
:root{
  --paper:#f5f1e6; --card:#fffdf6; --ink:#221b14; --muted:#7d7462;
  --line:#e3d9c2; --accent:#e8590c; --accent-soft:#ffe9d6;
  --green:#2f9e44; --red:#d94848;
}
*{box-sizing:border-box;margin:0;padding:0}
body{
  font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  background:var(--paper); color:var(--ink); min-height:100vh;
  background-image:radial-gradient(#ddd2b8 1px, transparent 1.2px);
  background-size:22px 22px;
}
.wrap{max-width:880px;margin:0 auto;padding:22px 16px 70px}
/* ---------- header ---------- */
header{display:flex;align-items:center;justify-content:space-between;gap:12px;
  padding:6px 2px 18px;border-bottom:2px solid var(--ink);margin-bottom:20px}
.brand{display:flex;align-items:center;gap:12px;min-width:0}
.logo{width:46px;height:46px;flex-shrink:0;background:var(--accent);color:#fff;
  border:2px solid var(--ink);border-radius:12px;display:grid;place-items:center;
  box-shadow:3px 3px 0 var(--ink)}
.logo svg{width:26px;height:26px}
h1{font-size:22px;letter-spacing:-.02em;white-space:nowrap}
.tag{font-size:12px;color:var(--muted);margin-top:2px}
.hdr-right{display:flex;align-items:center;gap:10px;position:relative;flex-shrink:0}
.badge{font-size:12px;font-weight:600;padding:5px 12px;border-radius:999px;
  background:#fff;border:2px solid var(--ink);white-space:nowrap}
.badge.on{background:#d8f3dc;color:#1e6f35}
.iconbtn{width:40px;height:40px;padding:0;justify-content:center;background:#fff;color:var(--ink)}
.iconbtn svg{width:18px;height:18px}
.iconbtn.danger{color:var(--red)}
.dropdown{position:absolute;top:50px;right:0;background:var(--card);
  border:2px solid var(--ink);border-radius:12px;min-width:190px;z-index:50;
  overflow:hidden;box-shadow:4px 4px 0 rgba(34,27,20,.18)}
.mi{display:flex;align-items:center;gap:10px;padding:13px 15px;font-size:14px;
  font-weight:600;cursor:pointer}
.mi svg{width:17px;height:17px;color:var(--accent)}
.mi:hover{background:var(--accent-soft)}
.mi + .mi{border-top:1px solid var(--line)}
/* ---------- cards ---------- */
.card{background:var(--card);border:2px solid var(--ink);border-radius:14px;
  padding:18px;margin-bottom:18px;box-shadow:5px 5px 0 rgba(34,27,20,.10)}
.cardhead{display:flex;align-items:center;gap:10px;margin-bottom:14px}
.cardicon{width:34px;height:34px;flex-shrink:0;border:2px solid var(--ink);
  border-radius:9px;display:grid;place-items:center;background:var(--accent-soft);color:var(--accent)}
.cardicon svg{width:18px;height:18px}
.cardhead h2{font-size:16px;letter-spacing:-.01em}
/* ---------- forms & buttons ---------- */
.row{display:flex;gap:10px;flex-wrap:wrap}
input,select{font-size:14px;padding:11px 13px;border-radius:9px;
  border:2px solid var(--ink);background:#fff;color:var(--ink);max-width:100%}
input:focus,select:focus{outline:2px solid var(--accent);outline-offset:1px}
input,select{flex:1;min-width:0}
select{overflow:hidden;text-overflow:ellipsis}
button{font-size:14px;font-weight:700;padding:11px 18px;border-radius:9px;
  border:2px solid var(--ink);background:var(--ink);color:#fff;cursor:pointer;
  display:inline-flex;align-items:center;justify-content:center;gap:8px;
  box-shadow:3px 3px 0 rgba(34,27,20,.25);white-space:nowrap}
button svg{width:16px;height:16px}
button:active{transform:translate(2px,2px);box-shadow:0 0 0 rgba(0,0,0,0)}
button.secondary{background:#fff;color:var(--ink)}
button.accent{background:var(--accent);border-color:var(--ink)}
button:disabled{opacity:.5;cursor:default;transform:none}
::placeholder{color:#a89e88}
/* ---------- addresses ---------- */
.addr{display:flex;flex-direction:column;gap:10px;padding:12px 14px;
  border:2px solid var(--ink);border-radius:10px;margin-top:10px;background:#fff}
.addr .a{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;
  overflow-wrap:anywhere;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.addr .actions{display:flex;gap:8px;width:100%}
.addr .actions .iconbtn{flex:1}
.dot{width:9px;height:9px;border-radius:50%;background:var(--accent);display:inline-block;flex-shrink:0}
.unread{font-size:11px;font-weight:700;background:var(--accent);color:#fff;
  padding:3px 10px;border-radius:999px;display:inline-flex;align-items:center;gap:6px;white-space:nowrap}
.unread .dot{background:#fff}
/* ---------- inbox ---------- */
.msg{padding:12px 14px;border:2px solid var(--ink);border-radius:10px;margin-top:10px;
  background:#fff;cursor:pointer;transition:background .12s}
.msg:hover{background:#fff8ec}
.msg.is-unread{border-left:8px solid var(--accent)}
.msg .top{display:flex;justify-content:space-between;gap:10px;align-items:baseline}
.msg .s{font-size:12px;color:var(--muted);overflow-wrap:anywhere;
  font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.msg .t{font-size:14px;margin-top:5px;overflow-wrap:break-word;font-weight:600}
.msg.is-unread .t{font-weight:800}
.detail{margin-top:12px;padding:0;background:#fff;border:2px solid var(--ink);
  border-radius:10px;overflow:hidden}
.detail .dhead{display:flex;align-items:center;justify-content:space-between;
  padding:12px 14px;border-bottom:2px solid var(--ink);background:var(--accent-soft)}
.detail .dhead b{font-size:14px}
.detail .meta{padding:12px 14px;border-bottom:1px dashed var(--line);font-size:13px}
.detail .meta .k{display:inline-block;width:52px;font-size:10px;font-weight:800;
  letter-spacing:.08em;color:var(--muted)}
.detail .meta div{margin:3px 0;overflow-wrap:anywhere}
.detail .subject{padding:12px 14px 0;font-weight:800;font-size:16px;letter-spacing:-.01em}
.detail pre{white-space:pre-wrap;overflow-wrap:break-word;font-size:13px;line-height:1.6;
  color:#3a3226;background:#f8f3e6;margin:12px 14px 14px;padding:12px;
  border:1px solid var(--line);border-radius:8px;max-height:420px;overflow:auto;
  font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
/* ---------- guide ---------- */
.muted{color:var(--muted);font-size:13px;line-height:1.6}
code{background:#f1e9d6;border:1px solid var(--line);padding:2px 7px;border-radius:6px;
  font-size:12.5px;overflow-wrap:break-word;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.tablewrap{overflow-x:auto;margin:12px -18px 0;padding:0 18px}
table{width:100%;min-width:560px;border-collapse:collapse;font-size:13px}
th{text-align:left;font-size:10.5px;letter-spacing:.09em;text-transform:uppercase;
  color:var(--muted);padding:8px;border-bottom:2px solid var(--ink);white-space:nowrap}
td{text-align:left;padding:10px 8px;border-bottom:1px solid var(--line);vertical-align:top}
pre.curl{background:#221b14;color:#f5eeda;padding:14px;border-radius:10px;font-size:12px;
  overflow-x:auto;white-space:pre;max-width:100%;margin-top:8px;line-height:1.7;
  font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.err{color:var(--red);font-size:13px;margin-top:10px;overflow-wrap:break-word;font-weight:600}
.ok{color:var(--green);font-size:13px;margin-top:10px;font-weight:600}
.empty{border:2px dashed var(--line);border-radius:10px;padding:20px;text-align:center;
  color:var(--muted);font-size:14px;margin-top:10px}
.hide{display:none}
footer{margin-top:26px;text-align:center;font-size:13px;color:var(--muted)}
footer a{color:var(--accent);font-weight:700;text-decoration:none}
footer a:hover{text-decoration:underline}
/* ---------- responsive ---------- */
@media (min-width:640px){
  .addr{flex-direction:row;align-items:center;justify-content:space-between}
  .addr .actions{width:auto}
  .addr .actions .iconbtn{flex:none}
  h1{font-size:24px}
}
@media (max-width:400px){
  h1{font-size:18px}
  .tag{display:none}
  .badge{font-size:11px;padding:4px 9px}
  .wrap{padding:14px 10px 50px}
  .card{padding:14px}
}
</style>
</head>
<body>
<div class="wrap">

<header>
  <div class="brand">
    <span class="logo"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/></svg></span>
    <div>
      <h1>Zero TempMail</h1>
      <p class="tag">email sekali pakai, tanpa drama.</p>
    </div>
  </div>
  <div class="hdr-right">
    <span class="badge" id="keyBadge">tanpa API key</span>
    <button class="iconbtn" id="menuBtn" aria-label="Menu"><svg viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="5" r="1.7"/><circle cx="12" cy="12" r="1.7"/><circle cx="12" cy="19" r="1.7"/></svg></button>
    <div class="dropdown hide" id="menuDrop">
      <div class="mi" id="mMails"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 16 12 14 15 10 15 8 12 2 12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/></svg>Mails</div>
      <div class="mi" id="mApi"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21 2-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0 3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>API Key</div>
    </div>
  </div>
</header>

<div id="viewMails">
  <section class="card">
    <div class="cardhead">
      <span class="cardicon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M5 12h14"/><path d="M12 5v14"/></svg></span>
      <h2>Alamat baru</h2>
    </div>
    <div class="row">
      <input id="newLocal" placeholder="nama-alamat" autocapitalize="off" autocomplete="off" spellcheck="false">
      <select id="domainSel"></select>
      <button id="createBtn" class="accent">Buat</button>
    </div>
    <div class="err" id="addrErr"></div>
    <div id="addrsList"><div class="empty">Memuat…</div></div>
  </section>

  <section class="card">
    <div class="cardhead">
      <span class="cardicon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 16 12 14 15 10 15 8 12 2 12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/></svg></span>
      <h2>Inbox</h2>
    </div>
    <div class="row">
      <select id="inboxSel"></select>
      <button id="loadInboxBtn" class="secondary"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M3 21v-5h5"/></svg>Muat</button>
    </div>
    <div class="err" id="inboxErr"></div>
    <div id="inboxList"></div>
    <div id="msgDetail"></div>
  </section>
</div>

<div id="viewApi" class="hide">
  <section class="card">
    <div class="cardhead">
      <span class="cardicon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21 2-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0 3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg></span>
      <h2>Kunci API</h2>
    </div>
    <p class="muted">Buat key lewat bot Telegram: <code>/apikey create nama</code>. Key hanya tersimpan di browser ini.</p>
    <div class="row" style="margin-top:10px">
      <input id="keyInput" type="password" placeholder="tmail_…" autocapitalize="off" autocomplete="off" spellcheck="false">
      <button id="saveKey">Simpan</button>
    </div>
    <div class="err" id="keyErr"></div>
  </section>

  <section class="card">
    <div class="cardhead">
      <span class="cardicon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 19.5v-15A2.5 2.5 0 0 1 6.5 2H20a1 1 0 0 1 1 1v18a1 1 0 0 1-1 1H6.5a1 1 0 0 1 0-5H20"/></svg></span>
      <h2>Panduan API</h2>
    </div>
    <p class="muted">Semua endpoint memakai header <code>X-API-Key</code>. Base URL: <code>https://temp.zsecret.me</code></p>
    <div class="tablewrap">
    <table>
    <tr><th>Method</th><th>Endpoint</th><th>Kegunaan</th></tr>
    <tr><td>POST</td><td><code>/api/v1/addresses</code></td><td>Buat alamat. Body: <code>{"local_part":"tokoku"}</code></td></tr>
    <tr><td>GET</td><td><code>/api/v1/addresses</code></td><td>Daftar alamat</td></tr>
    <tr><td>DELETE</td><td><code>/api/v1/addresses/:id</code></td><td>Hapus alamat</td></tr>
    <tr><td>GET</td><td><code>/api/v1/addresses/:id/messages</code></td><td>Daftar pesan</td></tr>
    <tr><td>GET</td><td><code>/api/v1/messages/:id</code></td><td>Baca pesan lengkap</td></tr>
    </table>
    </div>
    <p class="muted" style="margin-top:12px">Contoh curl:</p>
    <pre class="curl">curl -H "X-API-Key: tmail_..." \\
  https://temp.zsecret.me/api/v1/addresses</pre>
  </section>
</div>

<footer>
  Made by <a href="https://t.me/kakatiri">@kakatiri</a>
</footer>

</div>
<script>
var API = 'api/v1';
var ICONS = {
  copy: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>',
  inbox: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 16 12 14 15 10 15 8 12 2 12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/></svg>',
  trash: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/></svg>',
  x: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>',
  check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>'
};
function esc(s){ return String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function getKey(){ return localStorage.getItem('ztm_key') || ''; }
function setKey(k){ if(k) localStorage.setItem('ztm_key', k); else localStorage.removeItem('ztm_key'); }
function showErr(id, msg){ var t = (msg && msg.message) || msg || ''; document.getElementById(id).textContent = String(t); }
function refreshBadge(){
  var b = document.getElementById('keyBadge');
  if(getKey()){ b.textContent = 'API key tersimpan'; b.className = 'badge on'; }
  else { b.textContent = 'tanpa API key'; b.className = 'badge'; }
}
async function api(path, opts){
  var r = await fetch(API + path, Object.assign({ headers: { 'X-API-Key': getKey() } }, opts || {}));
  var j = await r.json().catch(function(){ return {}; });
  if(!r.ok){
    var e = j && j.error;
    var msg = typeof e === 'string' ? e : (e && (e.message || e.code)) || ('HTTP ' + r.status);
    throw new Error(msg);
  }
  return j;
}
async function loadDomains(){
  try{
    var d = await api('/domains');
    var sel = document.getElementById('domainSel');
    sel.innerHTML = '';
    (d.domains || []).forEach(function(x){
      var o = document.createElement('option');
      o.value = x; o.textContent = '@' + x;
      sel.appendChild(o);
    });
  }catch(e){ showErr('addrErr', e.message); }
}
async function loadAddrs(){
  showErr('addrErr', '');
  var box = document.getElementById('addrsList');
  try{
    var d = await api('/addresses');
    var list = d.addresses || [];
    var sel = document.getElementById('inboxSel');
    var cur = sel.value;
    sel.innerHTML = '';
    list.forEach(function(a){
      var o = document.createElement('option');
      o.value = a.id; o.textContent = a.email_address;
      sel.appendChild(o);
    });
    if(cur) sel.value = cur;
    if(list.length === 0){
      box.innerHTML = '<div class="empty">Belum ada alamat. Buat dulu di atas.</div>';
      return;
    }
    box.innerHTML = '';
    list.forEach(function(a){
      var div = document.createElement('div');
      div.className = 'addr';
      var badge = a.unread_count > 0
        ? '<span class="unread"><span class="dot"></span>' + a.unread_count + ' baru</span>' : '';
      div.innerHTML = '<span class="a">' + esc(a.email_address) + ' ' + badge + '</span>' +
        '<div class="actions">' +
        '<button class="iconbtn" data-act="copy" title="Salin alamat">' + ICONS.copy + '</button>' +
        '<button class="iconbtn" data-act="inbox" title="Buka inbox">' + ICONS.inbox + '</button>' +
        '<button class="iconbtn danger" data-act="del" title="Hapus">' + ICONS.trash + '</button>' +
        '</div>';
      div.querySelector('[data-act="copy"]').onclick = function(){
        var done = function(){ this.innerHTML = ICONS.check; var b = this;
          setTimeout(function(){ b.innerHTML = ICONS.copy; }, 1200); };
        if(navigator.clipboard && navigator.clipboard.writeText){
          navigator.clipboard.writeText(a.email_address).then(done.bind(this)).catch(function(){});
        } else {
          var t = document.createElement('textarea');
          t.value = a.email_address; document.body.appendChild(t); t.select();
          try{ document.execCommand('copy'); }catch(e){}
          document.body.removeChild(t); done.call(this);
        }
      };
      div.querySelector('[data-act="inbox"]').onclick = function(){
        document.getElementById('inboxSel').value = a.id;
        loadInbox();
      };
      div.querySelector('[data-act="del"]').onclick = async function(){
        if(!confirm('Hapus ' + a.email_address + ' beserta semua pesannya?')) return;
        try{ await api('/addresses/' + a.id, { method: 'DELETE' }); loadAddrs(); }
        catch(e){ showErr('addrErr', e.message); }
      };
      box.appendChild(div);
    });
  }catch(e){ showErr('addrErr', e.message); }
}
async function loadInbox(){
  showErr('inboxErr', '');
  var id = document.getElementById('inboxSel').value;
  var list = document.getElementById('inboxList');
  document.getElementById('msgDetail').innerHTML = '';
  if(!id){ list.innerHTML = '<div class="empty">Pilih alamat dulu.</div>'; return; }
  try{
    var d = await api('/addresses/' + id + '/messages');
    var msgs = d.messages || [];
    if(msgs.length === 0){
      list.innerHTML = '<div class="empty">Inbox kosong. Belum ada email masuk.</div>';
      return;
    }
    list.innerHTML = '';
    msgs.forEach(function(m){
      var div = document.createElement('div');
      div.className = 'msg' + (m.is_read ? '' : ' is-unread');
      div.innerHTML = '<div class="top"><span class="s">' + esc(m.sender) + '</span>' +
        '<span class="s">' + esc(m.received_at || '') + '</span></div>' +
        '<div class="t">' + esc(m.subject || '(tanpa subjek)') + '</div>';
      div.onclick = function(){ readMsg(m.id, div); };
      list.appendChild(div);
    });
  }catch(e){ showErr('inboxErr', e.message); }
}
async function readMsg(id, el){
  try{
    var m = await api('/messages/' + id);
    var d = document.getElementById('msgDetail');
    d.innerHTML = '<div class="detail">' +
      '<div class="dhead"><b>Isi pesan</b>' +
      '<button class="iconbtn" id="closeDetail" title="Tutup" style="width:32px;height:32px">' + ICONS.x + '</button></div>' +
      '<div class="meta">' +
      '<div><span class="k">KE</span>' + esc(m.address || '') + '</div>' +
      '<div><span class="k">DARI</span>' + esc(m.sender) + '</div>' +
      '<div><span class="k">WAKTU</span>' + esc(m.received_at || '') + '</div>' +
      '</div>' +
      '<div class="subject">' + esc(m.subject || '(tanpa subjek)') + '</div>' +
      '<pre>' + esc(m.body || '(kosong)') + '</pre></div>';
    document.getElementById('closeDetail').onclick = function(){ d.innerHTML = ''; };
    if(el) el.classList.remove('is-unread');
    d.scrollIntoView({ block: 'nearest' });
  }catch(e){ showErr('inboxErr', e.message); }
}
function showView(name){
  document.getElementById('viewMails').className = name === 'mails' ? '' : 'hide';
  document.getElementById('viewApi').className = name === 'api' ? '' : 'hide';
  document.getElementById('menuDrop').className = 'dropdown hide';
  if(name === 'mails' && getKey()){ loadDomains(); loadAddrs(); }
  window.scrollTo(0, 0);
}
document.getElementById('menuBtn').onclick = function(e){
  e.stopPropagation();
  document.getElementById('menuDrop').classList.toggle('hide');
};
document.getElementById('mMails').onclick = function(){ showView('mails'); };
document.getElementById('mApi').onclick = function(){ showView('api'); };
document.addEventListener('click', function(){
  document.getElementById('menuDrop').className = 'dropdown hide';
});
document.getElementById('saveKey').onclick = function(){
  var k = document.getElementById('keyInput').value.trim();
  if(!k){ showErr('keyErr', 'Tempel dulu API key-nya.'); return; }
  setKey(k); showErr('keyErr', ''); refreshBadge();
  loadDomains(); loadAddrs();
  document.getElementById('keyInput').value = '';
  showView('mails');
};
document.getElementById('createBtn').onclick = async function(){
  var local = document.getElementById('newLocal').value.trim().toLowerCase();
  var domain = document.getElementById('domainSel').value;
  if(!getKey()){ showErr('addrErr', 'Isi API key dulu di menu API Key (pojok kanan atas).'); return; }
  if(!local){ showErr('addrErr', 'Isi dulu nama alamatnya.'); return; }
  try{
    await api('/addresses', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-Key': getKey() },
      body: JSON.stringify({ local_part: local, domain: domain })
    });
    document.getElementById('newLocal').value = '';
    showErr('addrErr', '');
    loadAddrs();
  }catch(e){ showErr('addrErr', e.message); }
};
document.getElementById('loadInboxBtn').onclick = loadInbox;
document.getElementById('inboxSel').onchange = loadInbox;
refreshBadge();
if(getKey()){ loadDomains(); loadAddrs(); }
else {
  document.getElementById('addrsList').innerHTML =
    '<div class="empty">Isi API key dulu di menu <b>API Key</b> (pojok kanan atas).</div>';
}
</script>
</body>
</html>`;
