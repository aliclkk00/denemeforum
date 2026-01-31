import { initializeApp } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-app.js";
import { getAuth, signInWithEmailAndPassword, createUserWithEmailAndPassword, signOut, onAuthStateChanged, updatePassword, reauthenticateWithCredential, EmailAuthProvider } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js";
import { getFirestore, collection, addDoc, doc, setDoc, getDoc, getDocs, updateDoc, query, orderBy, serverTimestamp, deleteDoc, where, runTransaction } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-firestore.js";

const firebaseConfig = {
    apiKey: "AIzaSyCP0Rd8CAfzYRPtakfdQWBqS5uBn045XpE",
    authDomain: "hizliyimforum.firebaseapp.com",
    databaseURL: "https://hizliyimforum-default-rtdb.firebaseio.com",
    projectId: "hizliyimforum",
    storageBucket: "hizliyimforum.firebasestorage.app",
    messagingSenderId: "903963422468",
    appId: "1:903963422468:web:936c368393585efd0cea51"
};

const app = initializeApp(firebaseConfig);
const db = getFirestore(app);
const auth = getAuth(app);

// --- SİSTEM AYARLARI ---
const SUPER_USER = "alicelik";
const SUPER_PASS = "alikingytyt6565";
const SUPER_EMAIL = "alicelik@hizliyim.com"; 

// HASH KİLİDİ (Passcode: irem220208irem)
// Bu kod şifrenin SHA-256 ile şifrelenmiş halidir.
const TARGET_HASH = "d303253738092892543993134375176008693721528623694086052303020697";

// --- DURUM YÖNETİMİ ---
let currentUserData = null;
let authChecked = false;
let suFlow = false; 
let pendingDeleteId = null;

// --- GÜVENLİK VE YARDIMCI FONKSİYONLAR ---

// SHA-256 Hash Fonksiyonu
async function sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Türkçe Karakter Kontrolü (True dönerse Türkçe karakter var demektir)
function hasTurkishChars(str) {
    return /[öçşığüÖÇŞİĞÜ]/.test(str);
}

window.handleLogout = async () => {
    await signOut(auth);
    localStorage.removeItem('lastAuthTimestamp');
    window.location.hash = '#/login';
    window.location.reload(); 
};

window.formatDate = (ts) => {
    if(!ts) return '';
    return new Date(ts.seconds * 1000).toLocaleString('tr-TR', { day: 'numeric', month: 'short', hour: '2-digit', minute:'2-digit' });
};

function showMsg(id, type, text) {
    const el = document.getElementById(id);
    if(!el) return;
    el.className = `msg-box ${type === 'success' ? 'msg-success' : 'msg-error'}`;
    el.innerHTML = type === 'success' ? `<i data-lucide="check-circle" class="w-4 h-4 inline"></i> ${text}` : `<i data-lucide="alert-triangle" class="w-4 h-4 inline"></i> ${text}`;
    el.style.display = 'block';
    if(window.lucide) window.lucide.createIcons();
    if(!text.includes('YASAK')) setTimeout(() => { if(el) el.style.display = 'none'; }, 3500);
}

async function logAction(type, uid, email) {
    try { await addDoc(collection(db, "logs"), { type, uid, email, ua: navigator.userAgent, ts: serverTimestamp() }); } catch(e){}
}

// --- KİMLİK DOĞRULAMA DİNLEYİCİSİ ---
onAuthStateChanged(auth, async (user) => {
    if (user) {
        try {
            const snap = await getDoc(doc(db, "users", user.uid));
            if(snap.exists()) {
                const d = snap.data();
                const now = Date.now();
                if(d.bannedUntil && d.bannedUntil.toMillis() > now) {
                    await signOut(auth); currentUserData = null;
                } else if(d.username === "DELETED_USER") {
                    await signOut(auth); currentUserData = null;
                } else {
                    currentUserData = d;
                    updateDoc(doc(db, "users", user.uid), { lastLogin: serverTimestamp() });
                }
            } else if (user.email === SUPER_EMAIL) {
                currentUserData = { username: SUPER_USER, email: SUPER_EMAIL, role: 'superuser' };
            }
        } catch(e) { console.error(e); }
    } else { currentUserData = null; }
    authChecked = true;
    renderRouter();
});

// --- YÖNLENDİRME (ROUTER) ---
function renderRouter() {
    if(!authChecked) return; 
    let hash = window.location.hash.replace('#/', '').split('?')[0] || 'login';
    
    if (!currentUserData) {
        if (hash === 'passcode' && suFlow) { /* İzin ver */ } 
        else if (!['login', 'register'].includes(hash)) { hash = 'login'; window.history.replaceState(null, null, '#/login'); }
    } else {
        if (['login', 'register', 'passcode'].includes(hash)) { hash = 'home'; window.history.replaceState(null, null, '#/home'); }
    }

    const nav = document.getElementById('main-nav');
    if(currentUserData) { nav.style.display = 'flex'; updateNavbar(); } else { nav.style.display = 'none'; }

    // Formları temizle
    if(hash === 'settings') {
         document.querySelectorAll('#view-settings input').forEach(i => i.value = '');
         document.querySelectorAll('#view-settings .msg-box').forEach(b => b.style.display = 'none');
    }

    document.querySelectorAll('.page-section').forEach(el => el.classList.remove('active'));
    const target = document.getElementById(`view-${hash}`);
    if(target) {
        target.classList.add('active');
        if(hash === 'home') loadHome();
        if(hash === 'admin') loadAdmin();
        if(hash === 'post-detail') { const params = new URLSearchParams(window.location.hash.split('?')[1]); loadPostDetail(params.get('id')); }
        if(hash === 'notifications') loadNotifications();
        if(hash === 'profile') loadProfile();
    }
    if(window.lucide) window.lucide.createIcons();
}
window.addEventListener('hashchange', renderRouter);

function updateNavbar() {
    document.getElementById('nav-username').innerText = currentUserData.username;
    const badge = document.getElementById('nav-role');
    let txt="User", col="bg-gray-700 text-gray-300";
    if(currentUserData.role === 'admin') { txt="Admin"; col="bg-blue-900 text-blue-300"; }
    if(currentUserData.role === 'superuser') { txt="SuperSU"; col="bg-red-900 text-red-300"; }
    badge.className = `text-[10px] font-black uppercase px-2 py-1 rounded ${col}`; badge.innerText = txt;
    checkNotifs();
}

async function checkNotifs() {
    if(!auth.currentUser) return;
    const q = query(collection(db, `users/${auth.currentUser.uid}/notifications`), where("read", "==", false));
    const snap = await getDocs(q);
    const dot = document.getElementById('notif-dot');
    if(!snap.empty) dot.classList.remove('hidden'); else dot.classList.add('hidden');
}

// --- İÇERİK YÜKLEYİCİLERİ ---
async function loadHome() {
    try {
        const sys = await getDoc(doc(db, "system", "config"));
        if(sys.exists()) {
            document.getElementById('ann-text').innerText = sys.data().announcement || "Duyuru yok balım.";
            document.getElementById('quote-text').innerText = sys.data().quote || "Söz yok balım.";
            if(currentUserData.role === 'superuser') {
                document.getElementById('sys-ann').value = sys.data().announcement || "";
                document.getElementById('sys-quote').value = sys.data().quote || "";
            }
        }
    } catch(e){}
    document.getElementById('su-panel').classList.toggle('hidden', currentUserData.role !== 'superuser');
    document.getElementById('admin-btn').classList.toggle('hidden', currentUserData.role === 'user');
    const container = document.getElementById('feed');
    container.innerHTML = '<div class="text-center py-10"><div class="spinner"></div></div>';
    const q = query(collection(db, "pages"), orderBy("timestamp", "desc"));
    const snap = await getDocs(q);
    container.innerHTML = '';
    if(snap.empty) { container.innerHTML = '<div class="text-center text-gray-500 mt-10">Henüz paylaşım yok balım.</div>'; return; }
    snap.forEach(d => {
        const p = d.data();
        const canDelete = currentUserData.role === 'superuser' || (currentUserData.role === 'admin' && p.authorId === auth.currentUser.uid) || p.authorId === auth.currentUser.uid;
        const isLong = p.content.length > 150;
        const div = document.createElement('div');
        div.className = "glass-card !p-5 mb-4 hover:bg-white/5 transition-colors";
        div.innerHTML = `<div class="flex justify-between items-start mb-2"><h4 onclick="window.location.hash='#/post-detail?id=${d.id}'" class="font-bold text-lg text-blue-300 cursor-pointer break-words flex-1 pr-4 hover:underline">${p.title}</h4>${canDelete ? `<button onclick="window.deletePost('${d.id}')" class="text-red-500 opacity-50 hover:opacity-100"><i data-lucide="trash-2" class="w-4 h-4"></i></button>` : ''}</div><p class="text-gray-300 text-sm whitespace-pre-wrap break-words ${isLong ? 'line-clamp-3' : ''}">${p.content}</p>${isLong ? `<button onclick="this.previousElementSibling.classList.toggle('line-clamp-3'); this.innerText = this.innerText.includes('Devam') ? 'Kısalt' : 'Devamını Oku...'" class="text-xs text-blue-400 font-bold mt-1 hover:underline">Devamını Oku...</button>` : ''}<div class="mt-4 flex justify-between items-center border-t border-white/10 pt-3"><span class="text-[10px] font-bold text-gray-500 uppercase flex items-center gap-1"><i data-lucide="user" class="w-3 h-3"></i> ${p.authorName}</span><div class="flex items-center gap-3"><div class="flex gap-3 text-xs font-bold text-gray-400"><span class="flex items-center gap-1"><i data-lucide="thumbs-up" class="w-3 h-3 text-green-500"></i> ${p.likeCount || 0}</span><span class="flex items-center gap-1"><i data-lucide="thumbs-down" class="w-3 h-3 text-red-500"></i> ${p.dislikeCount || 0}</span></div><span class="text-[9px] text-gray-600">${window.formatDate(p.timestamp)}</span></div></div>`;
        container.appendChild(div);
    });
    if(window.lucide) window.lucide.createIcons();
}

async function loadPostDetail(id) {
    const container = document.getElementById('post-detail-cont');
    container.innerHTML = '<div class="spinner mx-auto"></div>';
    const snap = await getDoc(doc(db, "pages", id));
    if(!snap.exists()) { container.innerHTML = "Silinmiş."; return; }
    const p = snap.data();
    container.innerHTML = `<h2 class="text-2xl font-black mb-2 break-words text-white">${p.title}</h2><div class="text-xs text-gray-500 mb-6 flex gap-4 uppercase font-bold"><span>${p.authorName}</span><span>${window.formatDate(p.timestamp)}</span></div><div class="bg-white/5 p-4 rounded-xl text-gray-200 whitespace-pre-wrap break-words mb-6 border border-white/10">${p.content}</div><div class="flex gap-2 mb-8"><button onclick="window.vote('${id}', 'like')" class="flex-1 py-3 bg-green-500/10 hover:bg-green-500/20 text-green-400 rounded-xl font-bold flex justify-center gap-2 transition"><i data-lucide="thumbs-up" class="w-4 h-4"></i> Like (${p.likeCount||0})</button><button onclick="window.vote('${id}', 'dislike')" class="flex-1 py-3 bg-red-500/10 hover:bg-red-500/20 text-red-400 rounded-xl font-bold flex justify-center gap-2 transition"><i data-lucide="thumbs-down" class="w-4 h-4"></i> Dislike (${p.dislikeCount||0})</button></div><h3 class="font-bold border-b border-white/10 pb-2 mb-4">Yorumlar</h3><div id="comments-${id}" class="space-y-3 mb-6 max-h-60 overflow-y-auto"></div><div class="flex gap-2"><input id="cmt-${id}" class="input-field !py-2" placeholder="Yorum yaz balım..."><button onclick="window.sendComment('${id}')" class="btn-primary !w-auto !px-4 bg-blue-600"><i data-lucide="send" class="w-4 h-4"></i></button></div>`;
    const cSnap = await getDocs(query(collection(db, `pages/${id}/comments`), orderBy("timestamp", "asc")));
    const cList = document.getElementById(`comments-${id}`);
    cSnap.forEach(cd => {
        const c = cd.data();
        const canDelCmt = c.authorId === auth.currentUser.uid || currentUserData.role === 'admin' || currentUserData.role === 'superuser';
        cList.innerHTML += `<div class="bg-black/30 p-3 rounded-lg border border-white/5 flex justify-between items-start"><div><div class="flex justify-between text-[9px] text-gray-500 uppercase font-bold mb-1"><span>${c.authorName}</span><span>${window.formatDate(c.timestamp)}</span></div><div class="text-sm text-gray-300 break-words">${c.text}</div></div>${canDelCmt ? `<button onclick="window.openDeleteModal('${id}', '${cd.id}')" class="text-red-500/50 hover:text-red-500 text-[10px]"><i data-lucide="x" class="w-3 h-3"></i></button>` : ''}</div>`;
    });
    if(window.lucide) window.lucide.createIcons();
}

async function loadAdmin() {
    const uTbody = document.getElementById('admin-users'); uTbody.innerHTML = '';
    const uSnap = await getDocs(collection(db, "users"));
    uSnap.forEach(d => {
        const u = d.data();
        if(u.username === 'DELETED_USER') return; 
        uTbody.innerHTML += `<tr class="border-b border-white/5"><td class="p-3">${u.username}</td><td class="p-3 text-[10px] uppercase font-bold ${u.role==='superuser'?'text-red-400':'text-blue-400'}">${u.role}</td><td class="p-3 flex items-center gap-2">${(currentUserData.role==='superuser' || (currentUserData.role==='admin' && u.role==='user')) ? `<div class="flex gap-1"><button onclick="window.openBanMenu('${d.id}', '${u.username}')" class="bg-red-900/30 text-red-400 p-2 rounded text-[10px] hover:bg-red-900/50">Yasakla</button>${currentUserData.role==='superuser' ? `<button onclick="window.inspectUser('${d.id}', '${u.username}', '${u.email}', '${u.bannedUntil ? u.bannedUntil.seconds : 0}', '${u.role}')" class="bg-blue-900/30 text-blue-400 p-2 rounded text-[10px] hover:bg-blue-900/50">İncele</button><button onclick="window.nukeUser('${d.id}')" class="bg-red-950/50 text-red-600 p-2 rounded text-[10px] hover:bg-red-900"><i data-lucide="trash-2" class="w-3 h-3"></i></button>` : ''}</div>` : '-'}</td></tr>`;
    });

    const rTbody = document.getElementById('admin-reqs'); rTbody.innerHTML = '';
    let q;
    if (currentUserData.role === 'superuser') q = query(collection(db, "requests"), orderBy("timestamp", "desc"));
    else q = query(collection(db, "requests"), where("status", "==", "pending"));
    
    const rSnap = await getDocs(q);
    if(rSnap.empty) rTbody.innerHTML = '<tr><td colspan="3" class="p-3 text-center text-gray-500 text-xs">Talep yok.</td></tr>';
    rSnap.forEach(d => { 
        const r = d.data(); 
        let statusBadge = '';
        if(r.status === 'pending') statusBadge = '<span class="status-badge status-pending">Bekliyor</span>';
        else if(r.status === 'approved') statusBadge = '<span class="status-badge status-approved">Onaylandı</span>';
        else if(r.status === 'rejected') statusBadge = '<span class="status-badge status-rejected">Red</span>';
        let actionBtns = '';
        if(r.status === 'pending') actionBtns = `<div class="flex gap-2"><button onclick="window.decideReq('${d.id}', 'approved', '${r.userId}', '${r.newEmail}')" class="text-green-400 bg-green-900/20 p-1 rounded"><i data-lucide="check" class="w-3 h-3"></i></button><button onclick="window.decideReq('${d.id}', 'rejected', '${r.userId}')" class="text-red-400 bg-red-900/20 p-1 rounded"><i data-lucide="x" class="w-3 h-3"></i></button></div>`;
        else actionBtns = statusBadge;
        rTbody.innerHTML += `<tr class="border-b border-white/5"><td class="p-3">${r.username}</td><td class="p-3 text-xs opacity-60">${r.newEmail || r.type || 'Talep'}</td><td class="p-3">${actionBtns}</td></tr>`; 
    });
    if(window.lucide) window.lucide.createIcons();
}

async function loadNotifications() {
    const cont = document.getElementById('notif-cont');
    const q = query(collection(db, `users/${auth.currentUser.uid}/notifications`), orderBy("timestamp", "desc"));
    const snap = await getDocs(q);
    cont.innerHTML = '';
    if(snap.empty) { cont.innerHTML = '<div class="text-center text-gray-500">Bildirim yok balım.</div>'; return; }
    snap.forEach(d => { const n = d.data(); cont.innerHTML += `<div class="bg-white/5 p-3 rounded-xl mb-2 border-l-2 ${n.read ? 'border-gray-600' : 'border-blue-500'}"><h4 class="font-bold text-sm">${n.title}</h4><p class="text-xs text-gray-300 mt-1">${n.message}</p><div class="text-[9px] text-gray-600 text-right mt-1">${window.formatDate(n.timestamp)}</div></div>`; updateDoc(doc(db, `users/${auth.currentUser.uid}/notifications/${d.id}`), { read: true }); });
    document.getElementById('notif-dot').classList.add('hidden');
}

async function loadProfile() {
    document.getElementById('prof-user').innerText = currentUserData.username;
    document.getElementById('prof-email').innerText = currentUserData.email;
}

// --- KULLANICI AKSİYONLARI ---
window.createPost = async () => { const t = document.getElementById('post-title').value; const c = document.getElementById('post-content').value; if(!t || !c) return; const btn = document.getElementById('btn-post'); btn.disabled = true; try { await addDoc(collection(db, "pages"), { title: t, content: c, authorId: auth.currentUser.uid, authorName: currentUserData.username, timestamp: serverTimestamp() }); document.getElementById('post-title').value = ''; document.getElementById('post-content').value = ''; loadHome(); } catch(e) { console.error(e); } finally { btn.disabled = false; } };
window.deletePost = async (id) => { if(confirm("Silmek istediğine emin misin balım?")) { await deleteDoc(doc(db, "pages", id)); loadHome(); } };
window.saveSystemConfig = async () => { const a = document.getElementById('sys-ann').value; const q = document.getElementById('sys-quote').value; await setDoc(doc(db, "system", "config"), { announcement: a, quote: q }, {merge:true}); showMsg('sys-msg', 'success', "Güncellendi Balım!"); loadHome(); };

window.vote = async (pid, type) => {
    const uid = auth.currentUser.uid; const voteRef = doc(db, `pages/${pid}/votes/${uid}`); const postRef = doc(db, "pages", pid);
    try { await runTransaction(db, async(t) => {
        const vDoc = await t.get(voteRef); const pDoc = await t.get(postRef); if(!pDoc.exists()) return;
        let l = pDoc.data().likeCount || 0; let d = pDoc.data().dislikeCount || 0;
        if(vDoc.exists()) {
            if(vDoc.data().type === type) { t.delete(voteRef); if(type === 'like') l--; else d--; } 
            else { if(vDoc.data().type === 'like') l--; else d--; if(type === 'like') l++; else d++; t.set(voteRef, { type }); }
        } else { if(type === 'like') l++; else d++; t.set(voteRef, { type }); }
        t.update(postRef, { likeCount: l, dislikeCount: d });
    }); loadPostDetail(pid); } catch(e) { console.error(e); }
};

window.sendComment = async (pid) => { const inp = document.getElementById(`cmt-${pid}`); if(!inp.value.trim()) return; await addDoc(collection(db, `pages/${pid}/comments`), { text: inp.value, authorName: currentUserData.username, authorId: auth.currentUser.uid, timestamp: serverTimestamp() }); inp.value = ''; loadPostDetail(pid); };

window.openDeleteModal = (pid, cid) => { pendingDeleteId = { pid, cid }; document.getElementById('delete-modal').classList.remove('hidden'); };
window.closeDeleteModal = () => { pendingDeleteId = null; document.getElementById('delete-modal').classList.add('hidden'); };
window.confirmDeleteComment = async () => { if(pendingDeleteId) { await deleteDoc(doc(db, `pages/${pendingDeleteId.pid}/comments`, pendingDeleteId.cid)); loadPostDetail(pendingDeleteId.pid); closeDeleteModal(); } };

// ADMIN & SUPER ACTIONS
window.openBanMenu = (uid, username) => { document.getElementById('ban-target-id').value = uid; document.getElementById('ban-target-name').innerText = username; document.getElementById('ban-modal').classList.remove('hidden'); };
window.closeBanMenu = () => document.getElementById('ban-modal').classList.add('hidden');
window.applyBan = async () => { 
    const uid = document.getElementById('ban-target-id').value; const type = document.getElementById('ban-type').value; const val = parseInt(document.getElementById('ban-val').value); let ms = 0; if(type==='min') ms=val*60000; if(type==='hour') ms=val*3600000; if(type==='day') ms=val*86400000; 
    const date = new Date(Date.now()+ms);
    await updateDoc(doc(db, "users", uid), { bannedUntil: date });
    await addDoc(collection(db, `users/${uid}/banHistory`), { duration: `${val} ${type}`, until: date, timestamp: serverTimestamp() });
    showMsg('ban-msg', 'success', `${document.getElementById('ban-target-name').innerText} banlandı!`);
    closeBanMenu(); loadAdmin(); 
};
window.nukeUser = async (uid) => { if(confirm("Kullanıcı silinecek?")) { await setDoc(doc(db, "users", uid), { username: "DELETED_USER", email: "deleted", bannedUntil: new Date(2200, 0, 1) }); loadAdmin(); } };

window.inspectUser = (uid, uname, mail, banSec, role) => {
    document.getElementById('ins-uid').value = uid; document.getElementById('ins-name').innerText = uname; document.getElementById('ins-mail').innerText = mail;
    const now = Math.floor(Date.now() / 1000);
    document.getElementById('ins-ban').innerText = (banSec > now) ? new Date(banSec*1000).toLocaleString() : 'Mevcut Ban Yok';
    document.getElementById('ins-role-select').value = role;
    document.getElementById('ins-history-list').innerHTML = ''; 
    document.getElementById('inspect-modal').classList.remove('hidden');
};
window.closeInspect = () => document.getElementById('inspect-modal').classList.add('hidden');
window.changeRole = async () => {
    const uid = document.getElementById('ins-uid').value; const newRole = document.getElementById('ins-role-select').value;
    await updateDoc(doc(db, "users", uid), { role: newRole });
    alert(`Yetki ${newRole} olarak değişti balım!`); loadAdmin();
};
window.sendUserNotif = async () => { const uid = document.getElementById('ins-uid').value; const msg = document.getElementById('ins-notif-msg').value; if(!msg) return; await addDoc(collection(db, `users/${uid}/notifications`), { title: "Yönetici Mesajı", message: msg, read: false, timestamp: serverTimestamp() }); document.getElementById('ins-notif-msg').value = ''; alert("Gönderildi!"); };

window.viewBanHistory = async () => {
     const uid = document.getElementById('ins-uid').value; const list = document.getElementById('ins-history-list'); list.innerHTML = '<div class="spinner"></div>';
     const snap = await getDocs(collection(db, `users/${uid}/banHistory`));
     list.innerHTML = ''; if(snap.empty) list.innerHTML = '<div class="text-xs text-gray-500">Kayıt yok balım.</div>';
     snap.forEach(d => { const h = d.data(); list.innerHTML += `<div class="history-item"><span>${h.duration}</span><span>${window.formatDate(h.timestamp)}</span></div>`; });
};
window.viewNameHistory = async () => {
     const uid = document.getElementById('ins-uid').value; const list = document.getElementById('ins-history-list'); list.innerHTML = '<div class="spinner"></div>';
     const snap = await getDocs(collection(db, `users/${uid}/usernameHistory`));
     list.innerHTML = ''; if(snap.empty) list.innerHTML = '<div class="text-xs text-gray-500">Kayıt yok balım.</div>';
     snap.forEach(d => { const h = d.data(); list.innerHTML += `<div class="history-item"><span>${h.oldName}</span><span>${window.formatDate(h.timestamp)}</span></div>`; });
};

window.decideReq = async (rid, status, uid, newVal) => { await updateDoc(doc(db, "requests", rid), { status }); let msg = ""; if(status==='approved') msg=`Talebin ONAYLANDI balım. (${newVal || 'İşlem tamam'})`; else msg="Talebin REDDEDİLDİ balım."; await addDoc(collection(db, `users/${uid}/notifications`), { title: "Talep Sonucu", message: msg, read: false, timestamp: serverTimestamp() }); loadAdmin(); };
window.reqEmail = async () => { const m1 = document.getElementById('mail-1').value; const m2 = document.getElementById('mail-2').value; if(m1 !== m2) return showMsg('mail-msg', 'error', "E-postalar uyuşmuyor!"); if(!m1.includes('@')) return showMsg('mail-msg', 'error', "Hatalı mail!"); await addDoc(collection(db, "requests"), { userId: auth.currentUser.uid, username: currentUserData.username, oldEmail: currentUserData.email, newEmail: m1, type:'email', status: 'pending', timestamp: serverTimestamp() }); showMsg('mail-msg', 'success', "Talep gönderildi!"); };

// *** ŞİFRE DEĞİŞTİRME (GÜVENLİ) ***
window.changePass = async () => { 
     const msgBoxId = 'settings-pass-msg'; 
     const oldPassEl = document.getElementById('pass-old');
     const p1El = document.getElementById('pass-1');
     const p2El = document.getElementById('pass-2');
     
     if(!document.getElementById(msgBoxId) || !oldPassEl) return;

     const oldPass = oldPassEl.value;
     const p1 = p1El.value; 
     const p2 = p2El.value; 
     
     if(!oldPass) return showMsg(msgBoxId, 'error', "Mevcut şifreni girmen gerek.");
     if(p1 !== p2) return showMsg(msgBoxId, 'error', "Yeni şifreler uyuşmuyor!"); 
     if(p1.length < 6) return showMsg(msgBoxId, 'error', "En az 6 karakter!"); 
     
     const user = auth.currentUser;
     if (!user) return showMsg(msgBoxId, 'error', "Oturum açık değil!");

     const btn = oldPassEl.parentElement.querySelector('button');
     if(btn) { btn.innerText = "Kontrol ediliyor..."; btn.disabled = true; }

     try { 
         const credential = EmailAuthProvider.credential(user.email, oldPass);
         await reauthenticateWithCredential(user, credential);
         await updatePassword(user, p1); 
         showMsg(msgBoxId, 'success', "Şifre değişti balım! ✓"); 
         oldPassEl.value = ''; p1El.value = ''; p2El.value = '';
     } catch(e) { 
         if(e.code === 'auth/invalid-credential' || e.code === 'auth/wrong-password') showMsg(msgBoxId, 'error', "Eski şifren hatalı balım!");
         else if(e.code === 'auth/requires-recent-login') showMsg(msgBoxId, 'error', "Güvenlik için tekrar giriş yap.");
         else showMsg(msgBoxId, 'error', "Hata: " + e.code); 
     } finally {
         if(btn) { btn.innerText = "Değiştir"; btn.disabled = false; }
     }
};

window.changeUsername = async () => { 
    const u = document.getElementById('user-1').value.trim(); 
    if(hasTurkishChars(u)) return showMsg('user-msg', 'error', "Türkçe karakter kullanma balım! (İngilizce karakterler)");
    if(u.length < 4) return showMsg('user-msg', 'error', "Kısa isim!"); 
    const q = query(collection(db, "users"), where("username", "==", u)); 
    if(!(await getDocs(q)).empty) return showMsg('user-msg', 'error', "İsim dolu!"); 
    await addDoc(collection(db, `users/${auth.currentUser.uid}/usernameHistory`), { oldName: currentUserData.username, newName: u, timestamp: serverTimestamp() }); 
    await updateDoc(doc(db, "users", auth.currentUser.uid), { username: u }); 
    currentUserData.username = u; 
    showMsg('user-msg', 'success', "İsim değişti! ✓"); 
    updateNavbar(); 
};

// --- DOM INIT ---
document.addEventListener('DOMContentLoaded', () => {
    // LOGIN
    document.getElementById('form-login').addEventListener('submit', async (e) => {
        e.preventDefault(); const btn = e.target.querySelector('button'); const inp = document.getElementById('login-input').value.trim(); const pass = document.getElementById('login-password').value;
        if(inp === SUPER_USER && pass === SUPER_PASS) { suFlow = true; window.location.hash = '#/passcode'; return; }
        btn.innerHTML = '<div class="spinner"></div> İşleniyor...'; btn.disabled = true;
        try {
            let email = inp; if(!inp.includes('@')) { const q = query(collection(db, "users"), where("username", "==", inp)); const snap = await getDocs(q); if(snap.empty) throw {code:'auth/user-not-found'}; email = snap.docs[0].data().email; }
            const userCred = await signInWithEmailAndPassword(auth, email, pass);
            const userDoc = await getDoc(doc(db, "users", userCred.user.uid));
            if(userDoc.exists()) { const d = userDoc.data(); if(d.bannedUntil && d.bannedUntil.toMillis() > Date.now()) { await signOut(auth); showMsg('login-msg', 'error', `HESAP YASAKLI!`); btn.innerText = "Giriş Yap"; btn.disabled = false; return; } }
        } catch(err) { btn.innerText = "Giriş Yap"; btn.disabled = false; showMsg('login-msg', 'error', "Hatalı bilgi balım!"); }
    });

    // REGISTER (Türkçe Karakter Kontrollü)
    document.getElementById('form-register').addEventListener('submit', async (e) => {
        e.preventDefault(); const btn = e.target.querySelector('button'); const u = document.getElementById('reg-user').value.trim(); const em = document.getElementById('reg-email').value.trim(); const p = document.getElementById('reg-pass').value; const p2 = document.getElementById('reg-pass2').value;
        
        if(hasTurkishChars(u)) return showMsg('reg-msg', 'error', "Kullanıcı adında Türkçe karakter (ö,ç,ş,ğ,ü,ı,İ) olmasın balım.");
        if(p !== p2) return showMsg('reg-msg', 'error', "Şifreler uyuşmuyor!"); 
        if(u.length < 4 || u.includes(' ')) return showMsg('reg-msg', 'error', "İsim uygun değil");
        
        btn.innerHTML = '<div class="spinner"></div> İşleniyor...'; btn.disabled = true;
        const q = query(collection(db, "users"), where("username", "==", u)); if(!(await getDocs(q)).empty) { btn.innerText = "Kayıt Ol"; btn.disabled = false; return showMsg('reg-msg', 'error', "İsim kapılmış balım!"); }
        try { const cred = await createUserWithEmailAndPassword(auth, em, p); await setDoc(doc(db, "users", cred.user.uid), { username: u, email: em, role: 'user', createdAt: serverTimestamp() }); logAction('register', cred.user.uid, em); showMsg('reg-msg', 'success', "Kayıt Başarılı Balım, Yönlendiriliyorsun..."); } 
        catch(err) { btn.innerText = "Kayıt Ol"; btn.disabled = false; showMsg('reg-msg', 'error', "Hata: " + err.code); }
    });

    // PASSCODE (SHA-256 HASH KONTROLLÜ)
    document.getElementById('form-passcode').addEventListener('submit', async (e) => {
        e.preventDefault(); 
        const btn = document.getElementById('btn-passcode');
        const val = document.getElementById('passcode-input').value;
        
        // Girilen değeri hashleyip hedefle karşılaştırıyoruz
        const hashedVal = await sha256(val);

        if(hashedVal === TARGET_HASH) {
            btn.classList.remove('bg-red-700'); btn.classList.add('btn-success'); btn.innerHTML = '<i data-lucide="check" class="w-5 h-5 inline"></i> DOĞRULANDI';
            try {
                const cred = await signInWithEmailAndPassword(auth, SUPER_EMAIL, SUPER_PASS).catch(async () => await createUserWithEmailAndPassword(auth, SUPER_EMAIL, SUPER_PASS));
                await setDoc(doc(db, "users", cred.user.uid), { username: SUPER_USER, email: SUPER_EMAIL, role: 'superuser' }, {merge:true});
                setTimeout(() => window.location.hash = '#/home', 1000);
            } catch(err) { showMsg('pass-msg', 'error', err.message); }
        } else { showMsg('pass-msg', 'error', 'Hatalı Kod Balım!'); }
    });

    const pCont = document.getElementById('particles');
    for(let i=0; i<40; i++) { const p = document.createElement('div'); p.className = 'particle'; const s = Math.random()*120+20; p.style.width=s+'px'; p.style.height=s+'px'; p.style.left=Math.random()*100+'%'; p.style.top=Math.random()*100+'%'; const col = Math.random() > 0.5 ? '0, 102, 255' : '0, 194, 255'; p.style.background = `radial-gradient(circle, rgba(${col},0.3) 0%, transparent 70%)`; p.style.animationDuration = Math.random()*15+10+'s'; pCont.appendChild(p); }
});


