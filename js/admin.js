// ===== LOGIN (Firebase Auth — Admin Only) =====
const ADMIN_UID = '3YLY0Mg1fxU1kV5f2TZzZm9ga1h2';

async function doLogin() {
    const email = document.getElementById('loginUsername').value.trim();
    const pass  = document.getElementById('loginPassword').value;
    const err   = document.getElementById('loginError');
    const btn   = document.querySelector('.login-btn');

    if (!email || !pass) {
        err.textContent = 'Please enter your email and password.';
        err.style.display = 'block';
        return;
    }

    btn.textContent = 'Logging in…';
    btn.disabled = true;
    err.style.display = 'none';

    try {
        const { signInWithEmailAndPassword, signOut } = await import(
            'https://www.gstatic.com/firebasejs/11.0.0/firebase-auth.js'
        );

        const credential = await signInWithEmailAndPassword(window._firebaseAuth, email, pass);

        // Block anyone who is not the admin
        if (credential.user.uid !== ADMIN_UID) {
            await signOut(window._firebaseAuth);
            err.textContent = 'Access denied. Admins only.';
            err.style.display = 'block';
            document.getElementById('loginPassword').value = '';
            btn.textContent = 'Log In';
            btn.disabled = false;
            return;
        }

        // onAuthStateChanged in dashboard.html handles showing the app

    } catch (e) {
        const messages = {
            'auth/invalid-email':      'Invalid email address.',
            'auth/user-not-found':     'No admin account found with that email.',
            'auth/wrong-password':     'Incorrect password.',
            'auth/invalid-credential': 'Incorrect email or password.',
            'auth/too-many-requests':  'Too many attempts. Please try again later.',
        };
        err.textContent = messages[e.code] || 'Login failed. Please try again.';
        err.style.display = 'block';
        document.getElementById('loginPassword').value = '';
        btn.textContent = 'Log In';
        btn.disabled = false;
    }
}

async function doLogout() {
    const { signOut } = await import(
        'https://www.gstatic.com/firebasejs/11.0.0/firebase-auth.js'
    );
    await signOut(window._firebaseAuth);
    document.getElementById('app').style.display = 'none';
    document.getElementById('login-screen').style.display = 'flex';
    document.getElementById('loginUsername').value = '';
    document.getElementById('loginPassword').value = '';
    document.getElementById('loginError').style.display = 'none';
    document.querySelector('.login-btn').textContent = 'Log In';
    document.querySelector('.login-btn').disabled = false;
}

document.addEventListener('keydown', e => {
    if (e.key === 'Enter' && document.getElementById('login-screen').style.display !== 'none') doLogin();
});

// ===== NAVIGATION =====
function showPage(page) {
    document.querySelectorAll('.page-section').forEach(s => s.classList.remove('active'));
    const target = document.getElementById('page-' + page);
    if (target) target.classList.add('active');
    document.querySelectorAll('.sidebar-link').forEach(l => l.classList.remove('active'));
    const nav = document.getElementById('nav-' + page);
    if (nav) nav.classList.add('active');
}

// ===== APPROVE BOOKING =====
function approveBooking(btn) {
    btn.classList.add('approved');
    btn.textContent = 'Approved ✔';
    btn.disabled = true;
    const badge = btn.closest('tr').querySelector('.badge');
    if (badge) { badge.className = 'badge confirmed'; badge.textContent = 'Confirmed'; }
}

// ===== SETTINGS NAV =====
function highlightSettingsNav(el) {
    document.querySelectorAll('.settings-nav-link').forEach(l => l.classList.remove('active'));
    el.classList.add('active');
}
