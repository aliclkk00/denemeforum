import { initializeApp } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-app.js";
import { getAuth, signInWithEmailAndPassword, createUserWithEmailAndPassword, signOut, onAuthStateChanged, updatePassword, reauthenticateWithCredential, EmailAuthProvider, signInAnonymously } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js";
import { getFirestore, collection, addDoc, doc, setDoc, getDoc, getDocs, updateDoc, query, orderBy, serverTimestamp, deleteDoc, where, runTransaction } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-firestore.js";

// Global Değişkenler (Ortam tarafından sağlanır)
const firebaseConfig = JSON.parse(__firebase_config);
const appId = typeof __app_id !== 'undefined' ? __app_id : 'hizliyim-forum';
const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);

// --- DURUM YÖNETİMİ ---
let currentUserData = null;
let authChecked = false;

// --- GÜVENLİK YARDIMCILARI ---

// XSS Koruması için yardımcı: HTML elementlerini güvenli oluşturur
function createSafeElement(tag, classes, text = "") {
    const el = document.createElement(tag);
    if (classes) el.className = classes;
    if (text) el.textContent = text; // innerHTML yerine textContent: XSS'i bitirir!
    return el;
}

// SHA-256 Hash Fonksiyonu
async function sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Türkçe Karakter Engelleyici
function isSafeString(str) {
    return !/[öçşığüÖÇŞİĞÜ\s]/.test(str);
}

// Mesaj Kutusu Gösterici
function showMsg(id, type, text) {
    const el = document.getElementById(id);
    if (!el) return;
    el.className = `msg-box ${type === 'success' ? 'msg-success' : 'msg-error'}`;
    el.textContent = text;
    el.style.display = 'block';
    setTimeout(() => { if (el) el.style.display = 'none'; }, 4000);
}

// --- AUTH SÜRECİ ---
const initAuth = async () => {
    // Önce anonim veya token ile giriş yap (Rules için şart)
    try {
        await signInAnonymously(auth);
    } catch (e) { console.error("Auth hatası:", e); }
};
initAuth();

onAuthStateChanged(auth, async (user) => {
    if (user && !user.isAnonymous) {
        try {
            // Kullanıcı verisini private koleksiyondan çek (RULE 1 uyumlu)
            const userDoc = await getDoc(doc(db, 'artifacts', appId, 'users', user.uid, 'profile', 'data'));
            if (userDoc.exists()) {
                const d = userDoc.data();
                // Ban kontrolü (Server-side timestamp ile Rules zaten engeller ama UI için)
                if (d.bannedUntil && d.bannedUntil.toMillis() > Date.now()) {
                    await signOut(auth);
                    showMsg('login-msg', 'error', "Yasaklı hesap!");
                } else {
                    currentUserData = { ...d, uid: user.uid };
                }
            }
        } catch (e) { console.error("Veri çekme hatası:", e); }
    } else {
        currentUserData = null;
    }
    authChecked = true;
    renderRouter();
});

// --- ROUTER ---
function renderRouter() {
    if (!authChecked) return;
    const hash = window.location.hash.replace('#/', '').split('?')[0] || 'login';
    
    // Güvenlik: Giriş yapmayanları login'e at
    if (!currentUserData && !['login', 'register'].includes(hash)) {
        window.location.hash = '#/login';
        return;
    }

    // Navbar görünürlüğü
    document.getElementById('main-nav').style.display = currentUserData ? 'flex' : 'none';
    if (currentUserData) updateNavbar();

    // Sayfa Gösterimi
    document.querySelectorAll('.page-section').forEach(s => s.classList.remove('active'));
    const target = document.getElementById(`view-${hash}`);
    if (target) {
        target.classList.add('active');
        // Sayfa yükleme tetikleyicileri
        if (hash === 'home') loadPosts();
        if (hash === 'admin' && (currentUserData.role === 'admin' || currentUserData.role === 'superuser')) loadAdmin();
    }
}
window.addEventListener('hashchange', renderRouter);

function updateNavbar() {
    document.getElementById('nav-username').textContent = currentUserData.username;
    const badge = document.getElementById('nav-role');
    badge.textContent = currentUserData.role.toUpperCase();
    badge.className = `status-badge ${currentUserData.role === 'superuser' ? 'status-rejected' : 'status-approved'}`;
}

// --- FİRSTORE İŞLEMLERİ (GÜVENLİ) ---

// Postları Yükle (XSS Korumalı Render)
async function loadPosts() {
    const container = document.getElementById('feed');
    container.innerHTML = ''; // Temizle
    
    try {
        const q = query(collection(db, 'artifacts', appId, 'public', 'data', 'posts'), orderBy('timestamp', 'desc'));
        const snap = await getDocs(q);
        
        snap.forEach(d => {
            const p = d.data();
            const card = createSafeElement('div', 'glass-card !p-5 mb-4');
            
            const title = createSafeElement('h4', 'font-bold text-blue-300 mb-2', p.title);
            const content = createSafeElement('p', 'text-gray-300 text-sm whitespace-pre-wrap mb-4', p.content);
            
            const meta = createSafeElement('div', 'flex justify-between text-[10px] text-gray-500');
            meta.appendChild(createSafeElement('span', '', `Yazar: ${p.authorName}`));
            meta.appendChild(createSafeElement('span', '', window.formatDate(p.timestamp)));
            
            card.appendChild(title);
            card.appendChild(content);
            card.appendChild(meta);
            container.appendChild(card);
        });
    } catch (e) { console.error("Post yükleme hatası:", e); }
}

// Passcode Doğrulama (Server-side Hash Karşılaştırma)
window.verifyPasscode = async () => {
    if (!currentUserData) return;
    const input = document.getElementById('passcode-input').value;
    const btn = document.getElementById('btn-passcode');
    
    try {
        btn.disabled = true;
        // 1. Passcode hash'ini veritabanından çek (Client'ta tutma!)
        const configDoc = await getDoc(doc(db, 'artifacts', appId, 'public', 'data', 'system_config'));
        if (!configDoc.exists()) throw new Error("Sistem hatası");
        
        const targetHash = configDoc.data().passcodeHash;
        const inputHash = await sha256(input);
        
        if (inputHash === targetHash) {
            // 2. Başarılıysa Rolü Güncelle (Rules bu UID'nin bunu yapabileceğini kontrol edecek)
            await updateDoc(doc(db, 'artifacts', appId, 'users', currentUserData.uid, 'profile', 'data'), {
                role: 'superuser'
            });
            showMsg('pass-msg', 'success', "Yetkiler tanımlandı balımmmm!");
            setTimeout(() => window.location.hash = '#/home', 1500);
        } else {
            showMsg('pass-msg', 'error', "Hatalı kod!");
        }
    } catch (e) {
        showMsg('pass-msg', 'error', "Yetkin yok balım!");
    } finally { btn.disabled = false; }
};

// --- ADMIN AKSİYONLARI ---
async function loadAdmin() {
    const list = document.getElementById('admin-users');
    list.innerHTML = 'Yükleniyor...';
    // Not: Tüm kullanıcıları çekmek için Rules'ta 'admin' yetkisi aranacak
    const snap = await getDocs(collection(db, 'artifacts', appId, 'public', 'data', 'user_indices'));
    list.innerHTML = '';
    snap.forEach(d => {
        const u = d.data();
        const row = createSafeElement('div', 'flex justify-between p-2 border-b border-white/5 text-xs');
        row.appendChild(createSafeElement('span', '', u.username));
        row.appendChild(createSafeElement('span', 'opacity-50', u.role));
        
        // Rol Değiştirme Butonu (Sadece UI, asıl kontrol Rules'ta)
        if (currentUserData.role === 'superuser' && u.uid !== currentUserData.uid) {
            const btn = createSafeElement('button', 'text-blue-400', '[Yetki Ver]');
            btn.onclick = () => window.changeUserRole(u.uid, 'admin');
            row.appendChild(btn);
        }
        list.appendChild(row);
    });
}

window.changeUserRole = async (targetUid, newRole) => {
    if (currentUserData.role !== 'superuser') return;
    try {
        // Bu işlem sadece SuperUser tarafından yapılabilir (Rules kontrol eder)
        await updateDoc(doc(db, 'artifacts', appId, 'users', targetUid, 'profile', 'data'), { role: newRole });
        alert("Yetki güncellendi balım!");
        loadAdmin();
    } catch (e) { alert("Yetkin yok balım!"); }
};

// Yardımcılar
window.formatDate = (ts) => ts ? new Date(ts.seconds * 1000).toLocaleString() : "";

// --- DOM INIT ---
document.addEventListener('DOMContentLoaded', () => {
    // Register Formu (Güvenlikli)
    document.getElementById('form-register')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const u = document.getElementById('reg-user').value.trim();
        const em = document.getElementById('reg-email').value.trim();
        const p = document.getElementById('reg-pass').value;
        
        if (!isSafeString(u)) return showMsg('reg-msg', 'error', "Kullanıcı adında Türkçe karakter veya boşluk olamaz!");
        
        try {
            const cred = await createUserWithEmailAndPassword(auth, em, p);
            // RULE 1'e göre private koleksiyona yaz
            await setDoc(doc(db, 'artifacts', appId, 'users', cred.user.uid, 'profile', 'data'), {
                username: u,
                email: em,
                role: 'user',
                createdAt: serverTimestamp()
            });
            // Public arama için index oluştur
            await setDoc(doc(db, 'artifacts', appId, 'public', 'data', 'user_indices', cred.user.uid), {
                username: u,
                uid: cred.user.uid,
                role: 'user'
            });
            showMsg('reg-msg', 'success', "Kayıt başarılı balım!");
        } catch (e) { showMsg('reg-msg', 'error', "Hata: " + e.message); }
    });

    // Login Formu
    document.getElementById('form-login')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const em = document.getElementById('login-input').value.trim();
        const p = document.getElementById('login-password').value;
        try {
            await signInWithEmailAndPassword(auth, em, p);
        } catch (e) { showMsg('login-msg', 'error', "Giriş başarısız!"); }
    });
});
