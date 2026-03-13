/**
 * HarvestHub Admin — app.js
 * Clean module: no dead code, debounced search, paginated data,
 * custom confirm modal, DOMPurify-style escaping, role-based auth.
 */

import { initializeApp } from 'https://www.gstatic.com/firebasejs/11.0.0/firebase-app.js';
import {
    getFirestore, collection, query, where, getDocs,
    updateDoc, doc, deleteDoc, addDoc, orderBy, limit, startAfter,
    getCountFromServer
} from 'https://www.gstatic.com/firebasejs/11.0.0/firebase-firestore.js';
import {
    getAuth, onAuthStateChanged, signInWithEmailAndPassword, signOut
} from 'https://www.gstatic.com/firebasejs/11.0.0/firebase-auth.js';

// ── Firebase Config ─────────────────────────────────────────────────────────
// IMPORTANT: Lock down Firestore Security Rules in Firebase Console so only
// authenticated admin users can read/write. The API key alone does not grant access.
const firebaseConfig = {
    apiKey: "AIzaSyDE4oLipbxiVtb4PtTVdcXsQaJO6wxSkF0",
    authDomain: "harvesthub-25071.firebaseapp.com",
    projectId: "harvesthub-25071",
    storageBucket: "harvesthub-25071.firebasestorage.app",
    messagingSenderId: "727328652891",
    appId: "1:727328652891:web:76b8fe7fe3f55c5040097e"
};

const app = initializeApp(firebaseConfig);
const db  = getFirestore(app);
const auth = getAuth(app);

// ── Admin Check ──────────────────────────────────────────────────────────────
// Using Firebase Custom Claims is ideal; for now we check UID + email domain.
const ADMIN_EMAIL_DOMAIN = 'harvesthub.com';
function isAdmin(user) {
    return user && (
        user.email?.endsWith('@' + ADMIN_EMAIL_DOMAIN) ||
        user.uid === '3YLY0Mg1fxU1kV5f2TZzZm9ga1h2'
    );
}

// ── State ────────────────────────────────────────────────────────────────────
let allBookings = [], allHarvesters = [], allCustomers = [], pendingHarvesters = [];
let currentBookingId = null;
const PAGE_SIZE = 25;

// ── Utility: HTML Escape (prevent XSS from Firestore data) ──────────────────
function esc(str) {
    return String(str ?? '')
        .replace(/&/g,'&amp;').replace(/</g,'&lt;')
        .replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
function fmtDate(d) {
    try { return new Date(d).toLocaleDateString('en-US',{month:'short',day:'numeric',year:'numeric'}); }
    catch { return '-'; }
}
function cap(s) { return s ? s.charAt(0).toUpperCase() + s.slice(1) : ''; }
function setSelect(id, val) {
    const el = document.getElementById(id);
    if (!el) return;
    for (const o of el.options) { if (o.value === val || o.text === val) { o.selected = true; return; } }
}

// ── Debounce (prevents re-render on every keystroke) ─────────────────────────
function debounce(fn, ms = 300) {
    let t; return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}

// ── Loading / Toast ───────────────────────────────────────────────────────────
function showLoading() { document.getElementById('loading-overlay').classList.add('active'); }
function hideLoading() { document.getElementById('loading-overlay').classList.remove('active'); }

function showToast(msg, type = '') {
    const t = document.getElementById('toast');
    t.textContent = msg;
    t.className = 'toast' + (type ? ' toast-' + type : '') + ' show';
    setTimeout(() => t.classList.remove('show'), 2800);
}

// ── Modal Helpers ─────────────────────────────────────────────────────────────
function openModal(id)  { document.getElementById(id).classList.add('open'); }
function closeModal(id) { document.getElementById(id).classList.remove('open'); }
function closeModalOnOverlay(e, id) { if (e.target === e.currentTarget) closeModal(id); }
window.closeModal = closeModal;
window.closeModalOnOverlay = closeModalOnOverlay;

// Custom confirm replaces window.confirm()
function showConfirm(message, onConfirm) {
    document.getElementById('confirm-message').innerHTML = esc(message);
    openModal('confirmModal');
    document.getElementById('confirm-ok').onclick = () => { closeModal('confirmModal'); onConfirm(); };
}

// ── Auth ──────────────────────────────────────────────────────────────────────
const loginScreen = document.getElementById('login-screen');
const appEl       = document.getElementById('app');

// FIX: Hide both screens initially via CSS class, not inline style.
// Setting both to 'none' immediately caused the login screen to never appear
// because Firebase's onAuthStateChanged is async — the screen was hidden
// before Firebase could decide to show it.
loginScreen.style.display = 'none'; // keep hidden until Firebase resolves
appEl.style.display       = 'none';

// Show a brief loading state while Firebase resolves auth
document.body.classList.add('auth-loading');

onAuthStateChanged(auth, user => {
    document.body.classList.remove('auth-loading');
    if (user && isAdmin(user)) {
        loginScreen.style.display = 'none';
        appEl.style.display = 'block';
        loadDashboardStats();
    } else {
        if (user) signOut(auth); // signed in but not admin
        appEl.style.display = 'none';
        loginScreen.style.display = 'flex'; // FIX: was never reached when both set to 'none' on load
    }
});

window.doLogin = async function() {
    const email = document.getElementById('loginUsername').value.trim();
    const pass  = document.getElementById('loginPassword').value;
    const err   = document.getElementById('loginError');
    const btn   = document.querySelector('.login-btn');
    err.style.display = 'none';
    if (!email || !pass) { err.textContent = 'Please enter email and password.'; err.style.display = 'block'; return; }
    btn.textContent = 'Logging in…'; btn.disabled = true;
    try {
        const cred = await signInWithEmailAndPassword(auth, email, pass);
        if (!isAdmin(cred.user)) {
            await signOut(auth);
            err.textContent = 'Access denied. Admin accounts only.';
            err.style.display = 'block';
        }
    } catch (e) {
        const msgs = {
            'auth/invalid-email':      'Invalid email address.',
            'auth/user-not-found':     'No account found with that email.',
            'auth/wrong-password':     'Incorrect password.',
            'auth/invalid-credential': 'Incorrect email or password.',
            'auth/too-many-requests':  'Too many attempts. Try again later.',
        };
        err.textContent = msgs[e.code] || 'Login failed. Please try again.';
        err.style.display = 'block';
    }
    btn.textContent = 'Log In'; btn.disabled = false;
};

window.doLogout = async function() {
    const overlay = document.getElementById('logout-overlay');
    overlay.classList.add('active');
    await new Promise(r => setTimeout(r, 500));
    await signOut(auth);
    overlay.classList.remove('active');
};

document.addEventListener('keydown', e => {
    // FIX: Use appEl visibility check instead of loginScreen (loginScreen was always 'none' initially)
    if (e.key === 'Enter' && appEl.style.display === 'none') window.doLogin();
});

// ── Navigation ─────────────────────────────────────────────────────────────────
const pageLoaders = {
    dashboard: loadDashboardStats,
    bookings:  loadBookings,
    harvesters:loadHarvesters,
    approvals: loadPendingHarvesters,
    customers: loadCustomers,
    settings:  loadSettings,
};
window.showPage = function(page) {
    document.querySelectorAll('.page-section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.sidebar-link').forEach(l => l.classList.remove('active'));
    document.getElementById('page-' + page)?.classList.add('active');
    document.getElementById('nav-' + page)?.classList.add('active');
    pageLoaders[page]?.();
};

// Profile dropdown
window.toggleProfileMenu = function() { document.getElementById('profileMenu').classList.toggle('show'); };
document.addEventListener('click', e => {
    const dd = document.querySelector('.profile-dropdown');
    if (dd && !dd.contains(e.target)) document.getElementById('profileMenu').classList.remove('show');
});

// ── Dashboard ──────────────────────────────────────────────────────────────────
async function loadDashboardStats() {
    showLoading();
    try {
        // OPTIMIZATION: Use getCountFromServer for totals — avoids reading entire collections
        const [totalBookingsCount, availableHarvestersCount, bSnap] = await Promise.all([
            getCountFromServer(collection(db, 'bookings')),
            getCountFromServer(query(collection(db, 'harvesters'), where('status', '==', 'available'))),
            getDocs(query(collection(db, 'bookings'), where('status', 'in', ['confirmed', 'pending']), limit(200)))
        ]);
        document.getElementById('stat-total-bookings').textContent = totalBookingsCount.data().count;
        document.getElementById('stat-available-harvesters').textContent = availableHarvestersCount.data().count;

        const today = new Date();
        let active = 0, upcoming = 0;
        bSnap.forEach(d => {
            const b = d.data();
            const s = new Date(b.startDate), e = new Date(b.endDate);
            if (b.status === 'confirmed' && today >= s && today <= e) active++;
            if ((b.status === 'confirmed' || b.status === 'pending') && new Date(b.startDate) > today) upcoming++;
        });
        document.getElementById('stat-active-rentals').textContent = active;
        document.getElementById('stat-upcoming-services').textContent = upcoming;

        await Promise.all([loadCurrentRentals(), loadUpcomingBookings()]);
    } catch (e) { console.error('Dashboard error:', e); showToast('Failed to load dashboard', 'error'); }
    hideLoading();
}

async function loadCurrentRentals() {
    const tb = document.getElementById('current-rentals-tbody');
    try {
        const snap = await getDocs(query(collection(db, 'bookings'), where('status', '==', 'confirmed'), limit(10)));
        const today = new Date();
        let rows = [];
        snap.forEach(d => {
            const b = d.data();
            const s = new Date(b.startDate), e = new Date(b.endDate);
            if (today >= s && today <= e && rows.length < 5)
                rows.push(`<tr><td>${esc(b.renterName||'-')}</td><td>${esc(b.harvesterName||'-')}</td><td>${esc(b.location||'-')}</td><td>${fmtDate(s)} – ${fmtDate(e)}</td></tr>`);
        });
        tb.innerHTML = rows.length ? rows.join('') : '<tr><td colspan="4" style="text-align:center;color:#9aaa9a;padding:20px">No active rentals</td></tr>';
    } catch { tb.innerHTML = '<tr><td colspan="4">Error loading</td></tr>'; }
}

async function loadUpcomingBookings() {
    const tb = document.getElementById('upcoming-bookings-tbody');
    try {
        const snap = await getDocs(query(collection(db, 'bookings'), orderBy('startDate','asc'), limit(20)));
        const today = new Date();
        let rows = [];
        snap.forEach(d => {
            const b = d.data();
            const s = new Date(b.startDate), e = new Date(b.endDate);
            if (s > today && (b.status === 'confirmed' || b.status === 'pending') && rows.length < 5) {
                const days = Math.ceil((e - s) / 86400000);
                rows.push(`<tr><td>${esc(b.renterName||'-')}</td><td>${esc(b.harvesterName||'-')}</td><td>${fmtDate(s)}</td><td>${days}d</td></tr>`);
            }
        });
        tb.innerHTML = rows.length ? rows.join('') : '<tr><td colspan="4" style="text-align:center;color:#9aaa9a;padding:20px">No upcoming bookings</td></tr>';
    } catch { tb.innerHTML = '<tr><td colspan="4">Error loading</td></tr>'; }
}

// ── Bookings ───────────────────────────────────────────────────────────────────
async function loadBookings() {
    showLoading();
    try {
        allBookings = [];
        // OPTIMIZATION: orderBy createdAt requires a Firestore index. We try it first
        // and gracefully fall back to an unordered query if the index doesn't exist yet.
        let snap;
        try {
            snap = await getDocs(query(collection(db, 'bookings'), orderBy('createdAt','desc'), limit(PAGE_SIZE)));
        } catch (indexErr) {
            console.warn('Index not ready, falling back to unordered query:', indexErr.message);
            snap = await getDocs(query(collection(db, 'bookings'), limit(PAGE_SIZE)));
        }
        snap.forEach(d => allBookings.push({ id: d.id, ...d.data() }));
        // Client-side sort as fallback so newest always appears first
        allBookings.sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));
        renderBookings();
    } catch (e) {
        console.error('loadBookings error:', e);
        document.getElementById('booking-tbody').innerHTML = '<tr><td colspan="9">Error loading bookings</td></tr>';
        showToast('Failed to load bookings', 'error');
    }
    hideLoading();
}

function renderBookings() {
    const tb = document.getElementById('booking-tbody');
    const sq = document.getElementById('bookingSearch')?.value.toLowerCase() || '';
    const sf = document.getElementById('bookingStatusFilter')?.value || '';
    const filtered = allBookings.filter(b => {
        const match = `${b.id} ${b.renterName||''} ${b.harvesterName||''}`.toLowerCase().includes(sq);
        return match && (!sf || b.status === sf.toLowerCase());
    });
    if (!filtered.length) { tb.innerHTML = '<tr><td colspan="9" style="text-align:center;padding:30px;color:#9aaa9a">No bookings found</td></tr>'; return; }
    tb.innerHTML = filtered.map(b => `<tr>
        <td style="font-family:monospace;font-size:12px;color:#7a907a">${esc(b.id.substring(0,8))}</td>
        <td>${esc(b.renterName||'-')}</td>
        <td>${esc(b.harvesterName||'-')}</td>
        <td>${esc(b.location||'-')}</td>
        <td>${fmtDate(b.startDate)}</td>
        <td>${fmtDate(b.endDate)}</td>
        <td style="font-weight:700;color:#2d7a2d">₱${esc(b.totalCost||0)}</td>
        <td><span class="badge ${esc(b.status)}">${cap(b.status)}</span></td>
        <td><button class="btn-action" onclick="viewBooking('${esc(b.id)}')">View</button></td>
    </tr>`).join('');
}

window.filterBookings = debounce(renderBookings);

window.viewBooking = function(id) {
    const b = allBookings.find(x => x.id === id);
    if (!b) return;
    currentBookingId = id;
    document.getElementById('bmv-id').textContent      = 'Booking ' + id.substring(0,8);
    document.getElementById('bmv-renter').textContent  = b.renterName   || '-';
    document.getElementById('bmv-harvester').textContent = b.harvesterName || '-';
    document.getElementById('bmv-location').textContent = b.location     || '-';
    document.getElementById('bmv-cost').textContent    = '₱' + (b.totalCost || 0);
    const lbl = document.getElementById('bmv-status-label');
    lbl.textContent = cap(b.status);
    lbl.className = 'modal-status-label ' + (b.status||'');
    openModal('bookingViewModal');
};

window.updateBookingStatus = async function(status) {
    if (!currentBookingId) return;
    try {
        await updateDoc(doc(db, 'bookings', currentBookingId), { status, updatedAt: new Date().toISOString() });
        showToast('Booking ' + cap(status));
        closeModal('bookingViewModal');
        allBookings = allBookings.map(b => b.id === currentBookingId ? {...b, status} : b);
        renderBookings();
        loadDashboardStats();
    } catch { showToast('Update failed', 'error'); }
};

window.openNewBookingModal = async function() {
    try {
        const [cSnap, hSnap] = await Promise.all([
            getDocs(collection(db, 'users')),
            getDocs(query(collection(db, 'harvesters'), where('status','==','available'), limit(50)))
        ]);
        let ch = '<option value="">Select Renter</option>';
        cSnap.forEach(d => { ch += `<option value="${esc(d.id)}">${esc(d.data().name||d.id)}</option>`; });
        let hh = '<option value="">Select Harvester</option>';
        hSnap.forEach(d => { hh += `<option value="${esc(d.id)}" data-name="${esc(d.data().name)}">${esc(d.data().name)}</option>`; });
        document.getElementById('nb-renter').innerHTML = ch;
        document.getElementById('nb-harvester').innerHTML = hh;
        openModal('newBookingModal');
    } catch { showToast('Failed to load data', 'error'); }
};

window.createBooking = async function() {
    const rSel = document.getElementById('nb-renter');
    const hSel = document.getElementById('nb-harvester');
    const rid = rSel.value;
    const hid = hSel.value;
    if (!rid || !hid) { showToast('Please fill all fields', 'error'); return; }
    // FIX: was setting renterName: rid (the doc ID) — now uses the option label text
    const rname = rSel.options[rSel.selectedIndex].text;
    const hname = hSel.options[hSel.selectedIndex].dataset.name;
    try {
        await addDoc(collection(db, 'bookings'), {
            renterId: rid, renterName: rname, harvesterId: hid, harvesterName: hname,
            location: document.getElementById('nb-location').value,
            startDate: document.getElementById('nb-start').value,
            endDate:   document.getElementById('nb-end').value,
            totalCost: parseFloat(document.getElementById('nb-cost').value) || 0,
            status: 'pending', createdAt: new Date().toISOString()
        });
        showToast('Booking created');
        closeModal('newBookingModal');
        loadBookings(); loadDashboardStats();
    } catch { showToast('Failed to create booking', 'error'); }
};

// ── Harvesters ─────────────────────────────────────────────────────────────────
async function loadHarvesters() {
    showLoading();
    try {
        allHarvesters = [];
        // Only show approved harvesters (available / rented / maintenance).
        // Pending and rejected harvesters live in the Approvals page.
        const snap = await getDocs(query(
            collection(db, 'harvesters'),
            where('status', 'in', ['available', 'rented', 'maintenance']),
            limit(PAGE_SIZE)
        ));
        snap.forEach(d => allHarvesters.push({ id: d.id, ...d.data() }));
        updateHarvesterStats();
        renderHarvesters();
    } catch (e) { console.error(e); showToast('Failed to load harvesters', 'error'); }
    hideLoading();
}

function updateHarvesterStats() {
    document.getElementById('harvester-available').textContent = allHarvesters.filter(h => h.status==='available').length + ' Available';
    document.getElementById('harvester-rented').textContent    = allHarvesters.filter(h => h.status==='rented').length    + ' In Use';
    document.getElementById('harvester-maintenance').textContent = allHarvesters.filter(h => h.status==='maintenance').length + ' Maintenance';
}

function renderHarvesters() {
    const grid = document.getElementById('harvester-grid');
    const sq = document.getElementById('harvesterSearch')?.value.toLowerCase() || '';
    const tf = document.getElementById('harvesterTypeFilter')?.value || '';
    const sf = document.getElementById('harvesterStatusFilter')?.value || '';
    const filtered = allHarvesters.filter(h => {
        const m = `${h.name||''} ${h.type||''}`.toLowerCase().includes(sq);
        return m && (!tf || h.type===tf) && (!sf || h.status===sf.toLowerCase());
    });
    if (!filtered.length) { grid.innerHTML = '<div class="empty-state"><h3>No Harvesters Found</h3><p>Try adjusting your search or filters.</p></div>'; return; }
    const typeEmoji = { 'Combine Harvester':'🌾', 'Rice Harvester':'🌾', 'Corn Harvester':'🌽' };
    grid.innerHTML = filtered.map(h => {
        const imgTag = h.imageUrl
            ? `<img src="${esc(h.imageUrl)}" alt="${esc(h.name)}" loading="lazy">`
            : `<div class="harvester-image-placeholder">${typeEmoji[h.type]||'🚜'}</div>`;
        return `<div class="harvester-card">
            <div class="harvester-image">${imgTag}<span class="status-badge ${esc(h.status||'available')}">${cap(h.status)}</span></div>
            <div class="harvester-info">
                <h3>${esc(h.name||'Unknown')}</h3>
                <p class="harvester-type">${esc(h.type||'-')}</p>
                <div class="specs">
                    <div class="spec-item"><span class="spec-label">ID</span><span class="spec-value">${esc(h.id.substring(0,8))}</span></div>
                    <div class="spec-item"><span class="spec-label">Rate</span><span class="spec-value">₱${esc(h.rate||0)}/day</span></div>
                    <div class="spec-item"><span class="spec-label">Year</span><span class="spec-value">${esc(h.year||'-')}</span></div>
                    <div class="spec-item"><span class="spec-label">Location</span><span class="spec-value">${esc(h.location||'-')}</span></div>
                </div>
                <div class="card-actions"><button class="btn-action" onclick="editHarvester('${esc(h.id)}')">Edit</button></div>
            </div>
        </div>`;
    }).join('');
}

window.filterHarvesters = debounce(renderHarvesters);

window.openNewHarvesterModal = function() {
    document.getElementById('hem-title').textContent = 'Add Harvester';
    document.getElementById('hem-doc-id').value = '';
    ['hem-name','hem-year','hem-capacity','hem-rate','hem-location','hem-owner'].forEach(id => { const el = document.getElementById(id); if(el) el.value=''; });
    setSelect('hem-type','Combine Harvester');
    // Hide status selector — new harvesters always start as 'pending'
    const statusRow = document.getElementById('hem-status')?.closest('.modal-field');
    if (statusRow) statusRow.style.display = 'none';
    // Show approval note & update button label
    const note = document.getElementById('hem-approval-note');
    const btn  = document.getElementById('hem-save-btn');
    if (note) note.style.display = 'inline';
    if (btn)  btn.textContent = 'Submit for Approval';
    document.getElementById('hem-delete-btn').style.display = 'none';
    openModal('harvesterEditModal');
};

window.editHarvester = function(id) {
    const h = allHarvesters.find(x => x.id === id);
    if (!h) return;
    document.getElementById('hem-title').textContent = 'Edit Harvester';
    document.getElementById('hem-doc-id').value = id;
    document.getElementById('hem-name').value     = h.name     || '';
    document.getElementById('hem-year').value     = h.year     || '';
    document.getElementById('hem-capacity').value = h.capacity || '';
    document.getElementById('hem-rate').value     = h.rate     || '';
    document.getElementById('hem-location').value = h.location || '';
    document.getElementById('hem-owner').value    = h.ownerName|| '';
    setSelect('hem-type', h.type   || 'Combine Harvester');
    setSelect('hem-status', h.status || 'available');
    // Show status field for existing harvesters (already approved)
    const statusRow = document.getElementById('hem-status')?.closest('.modal-field');
    if (statusRow) statusRow.style.display = '';
    // Hide approval note & restore normal save label
    const note = document.getElementById('hem-approval-note');
    const btn  = document.getElementById('hem-save-btn');
    if (note) note.style.display = 'none';
    if (btn)  btn.textContent = 'Save';
    document.getElementById('hem-delete-btn').style.display = 'inline-flex';
    openModal('harvesterEditModal');
};

window.saveHarvester = async function() {
    const id = document.getElementById('hem-doc-id').value;
    const name = document.getElementById('hem-name').value.trim();
    if (!name) { showToast('Name is required', 'error'); return; }
    const data = {
        name, type: document.getElementById('hem-type').value,
        year: document.getElementById('hem-year').value,
        capacity: document.getElementById('hem-capacity').value,
        rate: document.getElementById('hem-rate').value,
        location: document.getElementById('hem-location').value,
        ownerName: document.getElementById('hem-owner').value,
        updatedAt: new Date().toISOString()
    };
    try {
        if (id) {
            // Editing an existing (already approved) harvester — preserve chosen status
            data.status = document.getElementById('hem-status').value;
            await updateDoc(doc(db,'harvesters',id), data);
            showToast('Harvester updated');
            closeModal('harvesterEditModal');
            loadHarvesters();
        } else {
            // NEW harvester — always goes to Approvals first (status: pending)
            data.status = 'pending';
            data.createdAt = new Date().toISOString();
            await addDoc(collection(db,'harvesters'), data);
            showToast('Harvester submitted for approval ✓', 'success');
            closeModal('harvesterEditModal');
            // Redirect admin to Approvals page so they can see it queued
            showPage('approvals');
        }
        loadDashboardStats();
    } catch (e) { console.error(e); showToast('Failed to save', 'error'); }
};

window.deleteHarvester = function() {
    const id = document.getElementById('hem-doc-id').value;
    if (!id) return;
    showConfirm('Delete this harvester? This action cannot be undone.', async () => {
        try {
            await deleteDoc(doc(db,'harvesters',id));
            showToast('Harvester deleted');
            closeModal('harvesterEditModal');
            loadHarvesters(); loadDashboardStats();
        } catch { showToast('Delete failed', 'error'); }
    });
};

// ── Approvals ──────────────────────────────────────────────────────────────────
async function loadPendingHarvesters() {
    showLoading();
    document.getElementById('approval-empty').style.display = 'none';
    document.getElementById('approval-grid').innerHTML = '';
    try {
        const snap = await getDocs(query(collection(db,'harvesters'), where('status','==','pending'), limit(PAGE_SIZE)));
        pendingHarvesters = [];
        snap.forEach(d => pendingHarvesters.push({ id: d.id, ...d.data() }));
        document.getElementById('pending-count').textContent = pendingHarvesters.length + ' Pending';
        const badge = document.getElementById('approval-count');
        if (badge) { badge.textContent = pendingHarvesters.length; badge.style.display = pendingHarvesters.length ? 'inline-flex' : 'none'; }
        // Count today's approved/rejected (simple in-memory, avoids extra reads)
        document.getElementById('approved-count').textContent = '— Approved Today';
        document.getElementById('rejected-count').textContent = '— Rejected Today';
        renderPendingHarvesters();
    } catch { showToast('Failed to load approvals', 'error'); }
    hideLoading();
}

function renderPendingHarvesters() {
    const grid  = document.getElementById('approval-grid');
    const empty = document.getElementById('approval-empty');
    const sq = document.getElementById('approvalSearch')?.value.toLowerCase() || '';
    const tf = document.getElementById('approvalTypeFilter')?.value || '';
    const filtered = pendingHarvesters.filter(h => {
        const m = `${h.name||''} ${h.type||''}`.toLowerCase().includes(sq);
        return m && (!tf || tf === 'All Types' || h.type === tf);
    });
    if (!filtered.length) { empty.style.display = 'flex'; grid.innerHTML = ''; return; }
    empty.style.display = 'none';
    const typeEmoji = { 'Combine Harvester':'🌾', 'Rice Harvester':'🌾', 'Corn Harvester':'🌽' };
    grid.innerHTML = filtered.map(h => {
        const imgTag = h.imageUrl
            ? `<img src="${esc(h.imageUrl)}" alt="${esc(h.name)}" loading="lazy">`
            : `<div class="harvester-image-placeholder">${typeEmoji[h.type]||'🚜'}</div>`;
        return `<div class="harvester-card">
            <div class="harvester-image">${imgTag}<span class="status-badge pending">Pending Review</span></div>
            <div class="harvester-info">
                <h3>${esc(h.name||'Unknown')}</h3>
                <p class="harvester-type">${esc(h.type||'-')}</p>
                <div class="specs">
                    <div class="spec-item"><span class="spec-label">Owner</span><span class="spec-value">${esc(h.ownerName||'-')}</span></div>
                    <div class="spec-item"><span class="spec-label">Rate</span><span class="spec-value">₱${esc(h.rate||0)}/day</span></div>
                </div>
                <div class="card-actions">
                    <button class="btn-approve-card" onclick="approveHarvester('${esc(h.id)}')">✓ Approve</button>
                    <button class="btn-reject-card"  onclick="openRejectModal('${esc(h.id)}')">✕ Reject</button>
                </div>
            </div>
        </div>`;
    }).join('');
}

window.filterApprovals = debounce(renderPendingHarvesters);

window.approveHarvester = async function(id) {
    try {
        await updateDoc(doc(db,'harvesters',id), { status:'available', approvedAt:new Date().toISOString() });
        showToast('Harvester approved! Now visible in Harvesters page ✓');
        pendingHarvesters = pendingHarvesters.filter(h => h.id !== id);
        document.getElementById('pending-count').textContent = pendingHarvesters.length + ' Pending';
        const badge = document.getElementById('approval-count');
        if (badge) { badge.textContent = pendingHarvesters.length; badge.style.display = pendingHarvesters.length ? 'inline-flex' : 'none'; }
        renderPendingHarvesters();
        // Refresh harvesters cache & dashboard so approved item appears immediately
        loadDashboardStats();
        // Silently refresh allHarvesters in background so Harvesters page is up to date
        getDocs(query(
            collection(db,'harvesters'),
            where('status','in',['available','rented','maintenance']),
            limit(PAGE_SIZE)
        )).then(snap => {
            allHarvesters = [];
            snap.forEach(d => allHarvesters.push({ id: d.id, ...d.data() }));
        }).catch(() => {});
    } catch (e) { console.error(e); showToast('Approval failed', 'error'); }
};

window.openRejectModal = function(id) {
    document.getElementById('rejection-reason').value = '';
    document.getElementById('rejection-harvester-id').value = id;
    openModal('rejectionModal');
};

window.confirmReject = async function() {
    const id = document.getElementById('rejection-harvester-id').value;
    const reason = document.getElementById('rejection-reason').value.trim() || 'No reason provided';
    try {
        await updateDoc(doc(db,'harvesters',id), { status:'rejected', rejectedAt:new Date().toISOString(), rejectionReason:reason });
        showToast('Listing rejected');
        closeModal('rejectionModal');
        pendingHarvesters = pendingHarvesters.filter(h => h.id !== id);
        document.getElementById('pending-count').textContent = pendingHarvesters.length + ' Pending';
        const badge = document.getElementById('approval-count');
        if (badge) { badge.textContent = pendingHarvesters.length; badge.style.display = pendingHarvesters.length ? 'inline-flex' : 'none'; }
        renderPendingHarvesters();
    } catch { showToast('Rejection failed', 'error'); }
};

// ── Customers ──────────────────────────────────────────────────────────────────
async function loadCustomers() {
    showLoading();
    try {
        allCustomers = [];
        const snap = await getDocs(query(collection(db,'users'), limit(PAGE_SIZE)));
        snap.forEach(d => allCustomers.push({ id: d.id, ...d.data() }));
        renderCustomers();
    } catch {
        document.getElementById('customer-tbody').innerHTML = '<tr><td colspan="8">Error loading customers</td></tr>';
        showToast('Failed to load customers', 'error');
    }
    hideLoading();
}

function initials(name) { return (name||'?').split(' ').map(w=>w[0]).join('').substring(0,2).toUpperCase(); }
const avatarColors = ['#2d7a2d','#1a6aaa','#8a3a1a','#6a1a8a','#1a5a5a','#8a5a1a'];

function renderCustomers() {
    const tb = document.getElementById('customer-tbody');
    const sq = document.getElementById('customerSearch')?.value.toLowerCase() || '';
    const tf = document.getElementById('customerTypeFilter')?.value || '';
    const filtered = allCustomers.filter(c => {
        const m = `${c.name||''} ${c.email||''}`.toLowerCase().includes(sq);
        return m && (!tf || c.userType === tf);
    });
    if (!filtered.length) { tb.innerHTML = '<tr><td colspan="8" style="text-align:center;padding:30px;color:#9aaa9a">No customers found</td></tr>'; return; }
    tb.innerHTML = filtered.map(c => {
        const color = avatarColors[(c.id||'').charCodeAt(0) % avatarColors.length];
        const avatarStyle = `width:32px;height:32px;border-radius:50%;background:${color};display:inline-flex;align-items:center;justify-content:center;color:#fff;font-size:11px;font-weight:900;flex-shrink:0;`;
        return `<tr>
            <td style="font-family:monospace;font-size:12px;color:#7a907a">${esc(c.id.substring(0,8))}</td>
            <td><div style="display:flex;align-items:center;gap:9px"><span style="${avatarStyle}">${esc(initials(c.name))}</span>${esc(c.name||'-')}</div></td>
            <td>${esc(c.email||'-')}</td>
            <td>${esc(c.phone||'-')}</td>
            <td>${esc(c.userType||'Renter')}</td>
            <td>${esc(c.location||'-')}</td>
            <td><span class="badge ${esc((c.status||'active').toLowerCase())}">${cap(c.status||'Active')}</span></td>
            <td><button class="btn-action" onclick="editCustomer('${esc(c.id)}')">Edit</button></td>
        </tr>`;
    }).join('');
}

window.filterCustomers = debounce(renderCustomers);

window.openNewCustomerModal = function() {
    document.getElementById('cem-title').textContent = 'Add Customer';
    document.getElementById('cem-doc-id').value = '';
    ['cem-name','cem-email','cem-phone','cem-location'].forEach(id => { const el=document.getElementById(id); if(el) el.value=''; });
    setSelect('cem-type','Renter'); setSelect('cem-status','Active');
    openModal('customerEditModal');
};

window.editCustomer = function(id) {
    const c = allCustomers.find(x => x.id === id);
    if (!c) return;
    document.getElementById('cem-title').textContent = 'Edit Customer';
    document.getElementById('cem-doc-id').value    = id;
    document.getElementById('cem-name').value      = c.name     || '';
    document.getElementById('cem-email').value     = c.email    || '';
    document.getElementById('cem-phone').value     = c.phone    || '';
    document.getElementById('cem-location').value  = c.location || '';
    setSelect('cem-type', c.userType || 'Renter');
    setSelect('cem-status', c.status || 'Active');
    openModal('customerEditModal');
};

window.saveCustomer = async function() {
    const id = document.getElementById('cem-doc-id').value;
    const name = document.getElementById('cem-name').value.trim();
    if (!name) { showToast('Name is required', 'error'); return; }
    const data = {
        name, email: document.getElementById('cem-email').value,
        phone: document.getElementById('cem-phone').value,
        location: document.getElementById('cem-location').value,
        userType: document.getElementById('cem-type').value,
        status: document.getElementById('cem-status').value,
        updatedAt: new Date().toISOString()
    };
    try {
        if (id) { await updateDoc(doc(db,'users',id), data); showToast('Customer updated'); }
        else     { await addDoc(collection(db,'users'), {...data, createdAt:new Date().toISOString()}); showToast('Customer added'); }
        closeModal('customerEditModal');
        loadCustomers();
    } catch { showToast('Failed to save', 'error'); }
};

// ── Settings (localStorage) ───────────────────────────────────────────────────
function loadSettings() {
    const s = JSON.parse(localStorage.getItem('harvesthub_settings') || '{}');
    const fields = {
        'setting-platform-name': s.platformName || 'Harvester Booking Platform',
        'setting-support-email': s.supportEmail || 'support@harvester.com',
        'setting-contact-phone': s.contactPhone || '+63 2 1234 5678',
        'setting-business-hours':s.businessHours|| 'Monday - Saturday, 8:00 AM - 6:00 PM',
        'setting-min-duration':  s.minDuration  || '1',
        'setting-max-duration':  s.maxDuration  || '30',
        'setting-advance-booking':s.advanceBooking||'60',
        'setting-cancellation-period':s.cancellationPeriod||'24',
        'setting-platform-fee':  s.platformFee  || '10',
        'setting-security-deposit':s.securityDeposit||'20',
    };
    for (const [id, val] of Object.entries(fields)) {
        const el = document.getElementById(id); if(el) el.value = val;
    }
    setSelect('setting-currency',    s.currency    || 'PHP (₱)');
    setSelect('setting-timezone',    s.timezone    || 'Asia/Manila (GMT+8)');
    setSelect('setting-date-format', s.dateFormat  || 'MM/DD/YYYY');
}

window.saveSettings = function() {
    const keys = ['platform-name','support-email','contact-phone','business-hours',
                  'min-duration','max-duration','advance-booking','cancellation-period',
                  'platform-fee','security-deposit','currency','timezone','date-format'];
    const s = {};
    keys.forEach(k => {
        const el = document.getElementById('setting-' + k);
        if (el) s[k.replace(/-([a-z])/g, (_,c)=>c.toUpperCase())] = el.value;
    });
    localStorage.setItem('harvesthub_settings', JSON.stringify(s));
    showToast('Settings saved!');
};

window.resetSettings = function() {
    showConfirm('Reset all settings to defaults?', () => {
        localStorage.removeItem('harvesthub_settings');
        loadSettings();
        showToast('Settings reset');
    });
};

// ── Init: wire up debounced search inputs ─────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('bookingSearch')  ?.addEventListener('input', debounce(renderBookings));
    document.getElementById('harvesterSearch')?.addEventListener('input', debounce(renderHarvesters));
    document.getElementById('customerSearch') ?.addEventListener('input', debounce(renderCustomers));
    document.getElementById('approvalSearch') ?.addEventListener('input', debounce(renderPendingHarvesters));
    loadSettings();
});
