
function toLocalDateTime(utcStr) {
    if (!utcStr) return '';
    const date = new Date(utcStr);
    return date.toLocaleString();
}

function toLocalDate(utcStr) {
    if (!utcStr) return '';
    const date = new Date(utcStr);
    return date.toLocaleDateString();
}

document.querySelectorAll('.datetime').forEach(el => {
    const utc = el.dataset.utc;
    if (utc) el.textContent = toLocalDateTime(utc);
});
document.querySelectorAll('.datetime-date').forEach(el => {
    const utc = el.dataset.utc;
    if (utc) el.textContent = toLocalDate(utc);
});

function switchTab(tab) {
    const tabName = tab.dataset.tab;
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    
    tab.classList.add('active');
    document.getElementById(tabName + '-tab').classList.add('active');
    
    if (tabName === 'users') {
        loadUsers();
    }
}

async function loadUsers() {
    const tbody = document.getElementById('usersTableBody');
    try {
        const response = await fetch('/api/admin/users');
        const users = await response.json();
        
        if (users.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty">No users</td></tr>';
            return;
        }
        
        tbody.innerHTML = users.map(user => `
            <tr>
                <td>${escapeHtml(user.email)}</td>
                <td>${escapeHtml(user.name)}</td>
                <td>
                    ${user.has_password ? '<span class="badge badge-local">Local</span>' : ''}
                    ${user.unity_id ? '<span class="badge badge-oauth">OAuth</span>' : ''}
                </td>
                <td>${user.is_admin ? 'Yes' : 'No'}</td>
                <td>${new Date(user.created_at).toLocaleString()}</td>
                <td>
                    ${user.has_password
                        ? `<button class="btn btn-small" data-action="reset-password" data-id="${escapeHtml(user.id)}">Reset Password</button>`
                        : ''}
                    <button class="btn btn-small btn-danger" data-action="delete-user" data-id="${escapeHtml(user.id)}" data-email="${escapeHtml(user.email)}">Delete</button>
                </td>
            </tr>
        `).join('');
    } catch (e) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty">Failed to load users</td></tr>';
    }
}

document.getElementById('createUserForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('userEmail').value;
    const name = document.getElementById('userName').value;
    const password = document.getElementById('userPassword').value;
    const isAdmin = document.getElementById('userIsAdmin').checked;
    
    try {
        const response = await fetch('/api/admin/users', {
            method: 'POST',
            headers: csrfHeaders({'Content-Type': 'application/json'}),
            body: JSON.stringify({email, name, password, is_admin: isAdmin})
        });
        
        if (response.ok) {
            alert('User created successfully');
            document.getElementById('createUserForm').reset();
            loadUsers();
        } else {
            const error = await response.json();
            alert('Failed to create user: ' + (error.detail || 'Unknown error'));
        }
    } catch (e) {
        alert('Failed to create user: ' + e.message);
    }
});


// Password reset modal: hidden input with eye-icon toggle
let _passwordModalUserId = null;

function openPasswordModal(userId) {
    _passwordModalUserId = userId;
    document.getElementById('passwordModal').style.display = 'block';
    const input = document.getElementById('newPasswordInput');
    input.value = '';
    setTimeout(() => input.focus(), 50);
}

function closePasswordModal() {
    document.getElementById('passwordModal').style.display = 'none';
    _passwordModalUserId = null;
}

function togglePasswordVisibility() {
    const input = document.getElementById('newPasswordInput');
    const eye = document.getElementById('passwordEye');
    if (input.type === 'password') {
        input.type = 'text';
        eye.textContent = '🙈';
    } else {
        input.type = 'password';
        eye.textContent = '👁';
    }
}

async function submitPasswordReset() {
    if (!_passwordModalUserId) return;
    const newPassword = document.getElementById('newPasswordInput').value;
    if (!newPassword) {
        alert('Please enter a new password');
        return;
    }

    try {
        const response = await fetch(`/api/admin/users/${_passwordModalUserId}`, {
            method: 'PATCH',
            headers: csrfHeaders({'Content-Type': 'application/json'}),
            body: JSON.stringify({password: newPassword})
        });

        if (response.ok) {
            closePasswordModal();
            loadUsers();
        } else {
            let msg = 'Unknown error';
            try {
                const error = await response.json();
                if (typeof error.detail === 'string') {
                    msg = error.detail;
                } else if (Array.isArray(error.detail)) {
                    msg = error.detail.map(e => e.msg || JSON.stringify(e)).join('; ');
                }
            } catch (e) {}
            alert('Failed to reset password: ' + msg);
        }
    } catch (e) {
        alert('Failed to reset password: ' + e.message);
    }
}

async function deleteUser(userId, email) {
    if (!confirm(`Delete user ${email}? This cannot be undone.`)) return;
    
    try {
        const response = await fetch(`/api/admin/users/${userId}`, {
            method: 'DELETE',
            headers: csrfHeaders()
        });
        
        if (response.ok) {
            alert('User deleted');
            loadUsers();
        } else {
            const error = await response.json();
            alert('Failed to delete user: ' + (error.detail || 'Unknown error'));
        }
    } catch (e) {
        alert('Failed to delete user');
    }
}

async function revokeToken(tokenId) {
    if (!confirm('Are you sure you want to revoke this token?')) return;
    
    const response = await fetch(`/api/admin/tokens/${tokenId}`, {
        method: 'DELETE',
        headers: csrfHeaders()
    });
    
    if (response.ok) {
        location.reload();
    } else {
        alert('Failed to revoke token');
    }
}

async function deleteToken(tokenId) {
    if (!confirm('Are you sure you want to permanently delete this token? This cannot be undone.')) return;
    
    const response = await fetch(`/api/admin/tokens/${tokenId}/permanent`, {
        method: 'DELETE',
        headers: csrfHeaders()
    });
    
    if (response.ok) {
        location.reload();
    } else {
        alert('Failed to delete token');
    }
}

async function deleteRevokedTokens() {
    if (!confirm('Are you sure you want to delete all revoked tokens? This cannot be undone.')) return;
    
    const response = await fetch('/api/admin/tokens/revoked', {
        method: 'DELETE',
        headers: csrfHeaders()
    });
    
    if (response.ok) {
        location.reload();
    } else {
        alert('Failed to delete revoked tokens');
    }
}

registerActions({
    'switch-tab': (el) => switchTab(el),
    'delete-revoked': () => deleteRevokedTokens(),
    'revoke-token': (el) => revokeToken(el.dataset.id),
    'delete-token': (el) => deleteToken(el.dataset.id),
    'reset-password': (el) => openPasswordModal(el.dataset.id),
    'delete-user': (el) => deleteUser(el.dataset.id, el.dataset.email),
    'toggle-password': () => togglePasswordVisibility(),
    'submit-password': () => submitPasswordReset(),
    'close-password': () => closePasswordModal(),
});

document.getElementById('newPasswordInput').addEventListener('keydown', (event) => {
    if (event.key === 'Enter') submitPasswordReset();
});
