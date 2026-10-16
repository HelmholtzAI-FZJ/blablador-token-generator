
let usersPage = 1;

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

async function loadUsers(page = 1) {
    const tbody = document.getElementById('usersTableBody');
    try {
        const response = await fetch(`/api/admin/users?page=${page}&page_size=100`);
        if (!response.ok) throw new Error('User listing failed');
        const users = await response.json();
        usersPage = page;
        document.getElementById('usersPrevious').disabled = page <= 1;
        document.getElementById('usersNext').disabled = users.length < 100;
        document.getElementById('usersPage').textContent = `Page ${page}`;
        
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
                    <button class="btn btn-small btn-danger" data-action="revoke-credentials" data-id="${escapeHtml(user.id)}">Revoke All Credentials</button>
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
    document.getElementById('newPasswordInput').value = '';
    document.getElementById('newPasswordInput').type = 'password';
    document.getElementById('passwordEye').textContent = '👁';
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
    if (Array.from(newPassword).length < 15 || new TextEncoder().encode(newPassword).length > 72) {
        alert('Use at least 15 characters and at most 72 UTF-8 bytes.');
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

async function revokeCredentials(userId) {
    if (!confirm('Revoke all API tokens and browser sessions for this user?')) return;
    try {
        const response = await fetch(`/api/admin/users/${encodeURIComponent(userId)}/revoke-credentials`, {
            method: 'POST', headers: csrfHeaders(),
        });
        if (!response.ok) throw new Error('Revocation failed');
        location.reload();
    } catch {
        alert('Credential revocation could not be completed. Please retry.');
    }
}

async function restoreOAuthAccount() {
    const subject = prompt('Enter the exact OAuth subject ID of the disabled account to restore:');
    if (!subject || !confirm('Allow this OAuth subject to sign in again?')) return;
    try {
        const response = await fetch('/api/admin/users/restore-oauth', {
            method: 'POST', headers: csrfHeaders({'Content-Type': 'application/json'}),
            body: JSON.stringify({subject}),
        });
        if (!response.ok) throw new Error('Restoration failed');
        alert('OAuth account restored. The user can sign in again.');
        loadUsers();
    } catch {
        alert('OAuth account restoration could not be completed.');
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
    'revoke-credentials': (el) => revokeCredentials(el.dataset.id),
    'restore-oauth': () => restoreOAuthAccount(),
    'users-previous': () => loadUsers(Math.max(1, usersPage - 1)),
    'users-next': () => loadUsers(usersPage + 1),
    'toggle-password': () => togglePasswordVisibility(),
    'submit-password': () => submitPasswordReset(),
    'close-password': () => closePasswordModal(),
});

document.getElementById('newPasswordInput').addEventListener('keydown', (event) => {
    if (event.key === 'Enter') submitPasswordReset();
});
