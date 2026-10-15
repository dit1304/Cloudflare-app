/**
 * Web UI — satu halaman SPA yang dilayani langsung dari Worker (tanpa build step).
 * Auth memakai API key yang sama dengan REST API (disimpan di localStorage browser).
 */
export const WEB_HTML = `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Zero TempMail</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;background:#0f1420;color:#e8ecf4;min-height:100vh}
.wrap{max-width:860px;margin:0 auto;padding:20px 16px 60px}
header{display:flex;align-items:center;justify-content:space-between;padding:14px 0;border-bottom:1px solid #232c44;margin-bottom:18px}
header h1{font-size:20px}
.badge{font-size:12px;padding:4px 10px;border-radius:20px;background:#232c44;color:#9aa7c7}
.badge.on{background:#123f2b;color:#4ade80}
.card{background:#161d31;border:1px solid #232c44;border-radius:12px;padding:16px;margin-bottom:16px}
.card h2{font-size:16px;margin-bottom:12px}
.row{display:flex;gap:8px;flex-wrap:wrap}
input,select,button{font-size:14px;padding:10px 12px;border-radius:8px;border:1px solid #2c3654;background:#0f1420;color:#e8ecf4}
input,select{flex:1;min-width:140px}
button{background:#2f6bff;border-color:#2f6bff;color:#fff;cursor:pointer;font-weight:600}
button:hover{background:#2559d6}
button.ghost{background:transparent;border-color:#2c3654;color:#9aa7c7}
button.danger{background:transparent;border-color:#7f2d3a;color:#f87171}
button:disabled{opacity:.5;cursor:default}
.addr{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:10px;border:1px solid #232c44;border-radius:8px;margin-top:8px;background:#101729}
.addr .a{font-family:monospace;font-size:13px;word-break:break-all}
.unread{background:#7c2d12;color:#fdba74;font-size:11px;padding:2px 8px;border-radius:12px;margin-left:8px;white-space:nowrap}
.msg{padding:10px;border:1px solid #232c44;border-radius:8px;margin-top:8px;background:#101729;cursor:pointer}
.msg.unreadmsg{border-left:3px solid #2f6bff}
.msg .s{font-size:13px;color:#9aa7c7}
.msg .t{font-size:14px;margin:2px 0}
.detail{margin-top:8px;padding:12px;background:#0b101d;border:1px solid #232c44;border-radius:8px}
.detail pre{white-space:pre-wrap;word-break:break-word;font-size:13px;color:#c9d3ea;max-height:400px;overflow:auto}
.muted{color:#9aa7c7;font-size:13px}
.err{color:#f87171;font-size:13px;margin-top:8px}
.ok{color:#4ade80;font-size:13px;margin-top:8px}
ol.guide{margin:8px 0 8px 20px;font-size:14px}
ol.guide li{margin-bottom:6px}
code{background:#0b101d;padding:2px 6px;border-radius:6px;font-size:13px}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:8px}
th,td{text-align:left;padding:8px;border-bottom:1px solid #232c44;vertical-align:top}
th{color:#9aa7c7;font-weight:600}
.hide{display:none}
.dropdown{position:absolute;top:46px;right:0;background:#161d31;border:1px solid #232c44;border-radius:10px;min-width:170px;z-index:50;overflow:hidden;box-shadow:0 8px 24px rgba(0,0,0,.5)}
.mi{padding:12px 14px;font-size:14px;cursor:pointer}
.mi:hover{background:#1d2540}
</style>
</head>
<body>
<div class="wrap">
<header>
<h1>📧 Zero TempMail</h1>
<div style="display:flex;align-items:center;gap:8px;position:relative">
<span class="badge" id="keyBadge">tanpa API key</span>
<button class="ghost" id="menuBtn" style="padding:8px 12px;font-size:18px;line-height:1">⋮</button>
<div class="dropdown hide" id="menuDrop">
<div class="mi" id="mMails">📧 Mails</div>
<div class="mi" id="mApi">🔑 API Key</div>
</div>
</div>
</header>

<div id="viewMails">
<div class="card">
<h2>📧 Alamat Email</h2>
<div class="row">
<input id="localPart" placeholder="nama (kosong = acak)" autocomplete="off">
<select id="domainSel"><option value="">memuat domain...</option></select>
<button id="createAddr">Buat</button>
</div>
<div class="err hide" id="addrErr"></div>
<div id="addrList"></div>
</div>

<div class="card">
<h2>📥 Inbox</h2>
<div class="row">
<select id="inboxSel"><option value="">pilih alamat...</option></select>
<button id="loadInbox">Muat</button>
</div>
<div class="err hide" id="inboxErr"></div>
<div id="msgList"></div>
<div id="msgDetail"></div>
</div>

</div>
<div id="viewApi" class="hide">
<div class="card">
<h2>🔑 Kunci API</h2>
<div class="row">
<input type="password" id="keyInput" placeholder="tmail_..." autocomplete="off">
<button id="saveKey">Simpan</button>
<button class="ghost" id="clearKey">Hapus</button>
</div>
<div class="muted" style="margin-top:10px">Cara mendapatkan key:</div>
<ol class="guide">
<li>Buka bot di Telegram</li>
<li>Kirim <code>/apikey create web</code></li>
<li>Bot membalas key sekali — copy lalu paste di atas</li>
</ol>
<div class="err hide" id="keyErr"></div>
</div>

<div class="card">
<h2>🔌 Panduan API</h2>
<div class="muted">Semua endpoint di bawah memakai header <code>X-API-Key</code>.</div>
<table>
<tr><th>Method</th><th>Endpoint</th><th>Kegunaan</th></tr>
<tr><td>POST</td><td><code>/api/v1/addresses</code></td><td>Buat alamat. Body: <code>{"local_part":"tokoku"}</code></td></tr>
<tr><td>GET</td><td><code>/api/v1/addresses</code></td><td>Daftar alamat</td></tr>
<tr><td>DELETE</td><td><code>/api/v1/addresses/:id</code></td><td>Hapus alamat</td></tr>
<tr><td>GET</td><td><code>/api/v1/addresses/:id/messages</code></td><td>Daftar pesan</td></tr>
<tr><td>GET</td><td><code>/api/v1/messages/:id</code></td><td>Baca pesan lengkap</td></tr>
</table>
<div class="muted" style="margin-top:10px">Contoh curl:</div>
<pre style="background:#0b101d;padding:10px;border-radius:8px;font-size:12px;overflow:auto">curl -H "X-API-Key: tmail_..." \\
  https://HOST/api/v1/addresses</pre>
</div>
</div>
<div class="muted" style="text-align:center;margin-top:4px"></div>
Made by <a href="https://t.me/kakatiri" style="color:#2f6bff">@kakatiri</a></div>

<script>
var API = 'api/v1';
function getKey(){ return localStorage.getItem('tmail_api_key') || ''; }
function setBadge(){
  var b = document.getElementById('keyBadge');
  if(getKey()){ b.textContent = 'API key tersimpan'; b.className = 'badge on'; }
  else { b.textContent = 'tanpa API key'; b.className = 'badge'; }
}
function esc(s){
  return String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function showErr(id, msg){
  var e = document.getElementById(id);
  if(!msg){ e.className = 'err hide'; e.textContent = ''; return; }
  e.className = 'err'; e.textContent = msg;
}
async function api(path, opts){
  opts = opts || {};
  var key = getKey();
  if(!key) throw new Error('Isi API key dulu di bagian atas.');
  var headers = { 'X-API-Key': key, 'Content-Type': 'application/json' };
  var res = await fetch(API + path, { method: opts.method || 'GET', headers: headers, body: opts.body });
  var data = null;
  try { data = await res.json(); } catch(e){}
  if(!res.ok) throw new Error((data && data.error && data.error.message) || ('HTTP ' + res.status));
  return data;
}
async function loadDomains(){
  try{
    var d = await api('/domains');
    var sel = document.getElementById('domainSel');
    sel.innerHTML = '';
    d.domains.forEach(function(x){
      var o = document.createElement('option'); o.value = x; o.textContent = x; sel.appendChild(o);
    });
  }catch(e){ showErr('addrErr', e.message); }
}
async function loadAddrs(){
  showErr('addrErr', '');
  try{
    var d = await api('/addresses');
    var list = document.getElementById('addrList');
    var sel = document.getElementById('inboxSel');
    list.innerHTML = ''; sel.innerHTML = '';
    if(!d.addresses.length){ list.innerHTML = '<div class="muted" style="margin-top:8px">Belum ada alamat.</div>'; return; }
    d.addresses.forEach(function(a){
      var div = document.createElement('div'); div.className = 'addr';
      var left = document.createElement('div');
      left.innerHTML = '<span class="a">' + esc(a.address) + '</span>' + (a.unread_count ? '<span class="unread">' + a.unread_count + ' baru</span>' : '');
      var right = document.createElement('div'); right.className = 'row';
      var bIn = document.createElement('button'); bIn.className = 'ghost'; bIn.textContent = 'Inbox';
      bIn.onclick = function(){ sel.value = String(a.id); loadInbox(); window.scrollTo(0, document.getElementById('inboxSel').offsetTop - 80); };
      var bDel = document.createElement('button'); bDel.className = 'danger'; bDel.textContent = 'Hapus';
      bDel.onclick = function(){ if(confirm('Hapus ' + a.address + '?')) delAddr(a.id); };
      right.appendChild(bIn); right.appendChild(bDel);
      div.appendChild(left); div.appendChild(right);
      list.appendChild(div);
      var o = document.createElement('option'); o.value = String(a.id); o.textContent = a.address; sel.appendChild(o);
    });
  }catch(e){ showErr('addrErr', e.message); }
}
async function createAddr(){
  showErr('addrErr', '');
  var lp = document.getElementById('localPart').value.trim();
  var dm = document.getElementById('domainSel').value;
  try{
    await api('/addresses', { method: 'POST', body: JSON.stringify({ local_part: lp || undefined, domain: dm || undefined }) });
    document.getElementById('localPart').value = '';
    await loadAddrs();
  }catch(e){ showErr('addrErr', e.message); }
}
async function delAddr(id){
  try{ await api('/addresses/' + id, { method: 'DELETE' }); await loadAddrs(); }
  catch(e){ showErr('addrErr', e.message); }
}
async function loadInbox(){
  showErr('inboxErr', '');
  document.getElementById('msgDetail').innerHTML = '';
  var id = document.getElementById('inboxSel').value;
  if(!id){ showErr('inboxErr', 'Pilih alamat dulu.'); return; }
  try{
    var d = await api('/addresses/' + id + '/messages?limit=30');
    var list = document.getElementById('msgList');
    list.innerHTML = '';
    if(!d.messages.length){ list.innerHTML = '<div class="muted" style="margin-top:8px">Inbox kosong.</div>'; return; }
    d.messages.forEach(function(m){
      var div = document.createElement('div');
      div.className = 'msg' + (m.is_read ? '' : ' unreadmsg');
      div.innerHTML = '<div class="s">' + esc(m.sender) + ' • ' + esc(m.received_at || '') + '</div><div class="t">' + esc(m.subject || '(tanpa subjek)') + '</div>';
      div.onclick = function(){ readMsg(m.id, div); };
      list.appendChild(div);
    });
  }catch(e){ showErr('inboxErr', e.message); }
}
async function readMsg(id, el){
  try{
    var m = await api('/messages/' + id);
    var d = document.getElementById('msgDetail');
    d.innerHTML = '<div class="detail"><div class="s muted">Ke: ' + esc(m.address || '') + '</div>' +
      '<div class="s muted">Dari: ' + esc(m.sender) + '</div>' +
      '<div class="s muted">Waktu: ' + esc(m.received_at || '') + '</div>' +
      '<div style="font-weight:700;margin:6px 0">' + esc(m.subject || '(tanpa subjek)') + '</div>' +
      '<pre>' + esc(m.body || '(kosong)') + '</pre></div>';
    if(el && el.classList) el.classList.remove('unreadmsg');
    d.scrollIntoView();
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
  var v = document.getElementById('keyInput').value.trim();
  if(!v){ showErr('keyErr', 'Paste API key dulu.'); return; }
  localStorage.setItem('tmail_api_key', v);
  document.getElementById('keyInput').value = '';
  showErr('keyErr', ''); setBadge(); loadDomains(); loadAddrs();
};
document.getElementById('clearKey').onclick = function(){
  localStorage.removeItem('tmail_api_key'); setBadge();
};
document.getElementById('createAddr').onclick = createAddr;
document.getElementById('loadInbox').onclick = loadInbox;
setBadge();
if(getKey()){ loadDomains(); loadAddrs(); }
</script>
</body>
</html>`;
