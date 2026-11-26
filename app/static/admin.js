
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
    if (tabName === 'courses') {
        loadCourses();
    }
    if (tabName === 'applications') {
        loadApplications();
    }
}

// Confirmations name the account by what identifies it: the OAuth subject
// (a provider email may be unverified and shared) or the local email.
function describeAccount(user) {
    if (user.is_course_user) return `${user.email}, course user`;
    return user.unity_id
        ? `${user.name} <${user.email}>, OAuth subject ${user.unity_id}`
        : `${user.name} <${user.email}>, local account`;
}

async function loadUsers(page = 1) {
    const tbody = document.getElementById('usersTableBody');
    try {
        const params = new URLSearchParams({page, page_size: 100});
        const search = document.getElementById('userSearch').value.trim();
        if (search) params.set('q', search);
        const response = await fetch(`/api/admin/users?${params}`);
        if (!response.ok) throw new Error('User listing failed');
        const users = await response.json();
        usersPage = page;
        document.getElementById('usersPrevious').disabled = page <= 1;
        document.getElementById('usersNext').disabled = response.headers.get('X-Has-More') !== 'true';
        document.getElementById('usersPage').textContent = `Page ${page}`;
        
        if (users.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" class="empty">${search ? 'No users match' : 'No users'}</td></tr>`;
            return;
        }
        
        tbody.innerHTML = users.map(user => `
            <tr>
                <td>${escapeHtml(user.email)}</td>
                <td>${escapeHtml(user.name)}</td>
                <td>
                    ${user.is_course_user ? '<span class="badge badge-course" title="Created by a course invitation; cannot sign in">Course</span>' : ''}
                    ${user.has_password ? '<span class="badge badge-local">Local</span>' : ''}
                    ${user.unity_id
                        ? `<span class="badge badge-oauth">OAuth</span><code class="subject" title="OAuth subject">${escapeHtml(user.unity_id)}</code>`
                        : ''}
                </td>
                <td>${user.is_admin ? 'Yes' : 'No'}</td>
                <td>${user.is_teacher ? 'Yes' : 'No'}</td>
                <td>${new Date(user.created_at).toLocaleString()}</td>
                <td>
                    ${user.has_password
                        ? `<button class="btn btn-small" data-action="reset-password" data-id="${escapeHtml(user.id)}">Reset Password</button>`
                        : ''}
                    ${user.is_course_user ? '' : `<button class="btn btn-small" data-action="toggle-admin" data-id="${escapeHtml(user.id)}" data-account="${escapeHtml(describeAccount(user))}" data-admin="${user.is_admin}">${user.is_admin ? 'Remove Admin' : 'Make Admin'}</button>
                    <button class="btn btn-small" data-action="toggle-teacher" data-id="${escapeHtml(user.id)}" data-account="${escapeHtml(describeAccount(user))}" data-teacher="${user.is_teacher}">${user.is_teacher ? 'Remove Teacher' : 'Make Teacher'}</button>`}
                    <button class="btn btn-small btn-danger" data-action="revoke-credentials" data-id="${escapeHtml(user.id)}" data-account="${escapeHtml(describeAccount(user))}">Revoke All Credentials</button>
                    <button class="btn btn-small btn-danger" data-action="delete-user" data-id="${escapeHtml(user.id)}" data-account="${escapeHtml(describeAccount(user))}">Delete</button>
                </td>
            </tr>
        `).join('');
    } catch (e) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty">Failed to load users</td></tr>';
    }
}

document.getElementById('createUserForm')?.addEventListener('submit', async (e) => {
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
            alert('Failed to create user: ' + await errorMessage(response));
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
            loadUsers(usersPage);
        } else {
            alert('Failed to reset password: ' + await errorMessage(response));
        }
    } catch (e) {
        alert('Failed to reset password: ' + e.message);
    }
}

// Role changes end the user's sessions, including one's own.
async function toggleAdmin(userId, account, isAdmin) {
    const question = isAdmin
        ? `Remove administrator rights from ${account}?`
        : `Grant administrator rights to ${account}?`;
    if (!confirm(question + ' Their current sessions will be signed out.')) return;
    try {
        const response = await fetch(`/api/admin/users/${encodeURIComponent(userId)}`, {
            method: 'PATCH',
            headers: csrfHeaders({'Content-Type': 'application/json'}),
            body: JSON.stringify({is_admin: !isAdmin}),
        });
        if (!response.ok) throw new Error(await errorMessage(response));
        const self = document.querySelector('meta[name="current-user-id"]').content;
        if (userId === self) {
            window.location.href = '/';
            return;
        }
        loadUsers(usersPage);
    } catch (error) {
        alert('Role change failed: ' + error.message);
    }
}

async function revokeCredentials(userId, account) {
    if (!confirm(`Revoke all API tokens and browser sessions of ${account}?`)) return;
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

async function deleteUser(userId, account) {
    if (!confirm(`Delete ${account}? This cannot be undone.`)) return;
    
    try {
        const response = await fetch(`/api/admin/users/${userId}`, {
            method: 'DELETE',
            headers: csrfHeaders()
        });
        
        if (response.ok) {
            alert('User deleted');
            loadUsers(usersPage);
        } else {
            alert('Failed to delete user: ' + await errorMessage(response));
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

async function takeOverApplication(applicationId, name) {
    if (!confirm(`Become an owner of "${name}"? You can then add owners from your dashboard.`)) return;
    const response = await fetch(`/api/admin/applications/${encodeURIComponent(applicationId)}/take-over`, {
        method: 'POST', headers: csrfHeaders(),
    });
    if (response.ok) {
        location.reload();
    } else {
        alert(`Failed to take over application: ${await errorMessage(response)}`);
    }
}

async function deleteOrphanedApplication(applicationId, name) {
    if (!confirm(`Delete "${name}" and all its tokens? Services using them stop working. This cannot be undone.`)) return;
    const response = await fetch(`/api/admin/applications/${encodeURIComponent(applicationId)}`, {
        method: 'DELETE', headers: csrfHeaders(),
    });
    if (response.ok) {
        location.reload();
    } else {
        alert(`Failed to delete application: ${await errorMessage(response)}`);
    }
}

async function toggleTeacher(userId, account, isTeacher) {
    const question = isTeacher
        ? `Remove teacher rights from ${account}? Their running course is closed and its tokens revoked.`
        : `Allow ${account} to run courses?`;
    if (!confirm(question)) return;
    const response = await fetch(`/api/admin/users/${encodeURIComponent(userId)}`, {
        method: 'PATCH',
        headers: csrfHeaders({'Content-Type': 'application/json'}),
        body: JSON.stringify({is_teacher: !isTeacher}),
    });
    if (!response.ok) alert('Teacher change failed: ' + await errorMessage(response));
    loadUsers(usersPage);
}

let coursesPage = 1;

async function loadCourses(page = 1) {
    const tbody = document.getElementById('coursesTableBody');
    try {
        const response = await fetch(`/api/admin/courses?page=${page}&page_size=100`);
        if (!response.ok) throw new Error(await errorMessage(response));
        const courses = await response.json();
        coursesPage = page;
        document.getElementById('coursesPrevious').disabled = page <= 1;
        document.getElementById('coursesNext').disabled = response.headers.get('X-Has-More') !== 'true';
        if (courses.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty">No courses</td></tr>';
            return;
        }
        tbody.innerHTML = courses.map(course => `
            <tr>
                <td>${escapeHtml(course.name)}</td>
                <td>${course.teacher_email ? `${escapeHtml(course.teacher_name)} &lt;${escapeHtml(course.teacher_email)}&gt;` : '<span class="muted">deleted</span>'}</td>
                <td>${toLocalDate(course.starts_at)} – ${toLocalDateTime(course.ends_at)}</td>
                <td>${course.seats_claimed} / ${course.max_seats}</td>
                <td>${course.suspended_at ? `Closed: ${escapeHtml(course.suspended_reason || '')}` : (course.active ? 'Active' : 'Ended')}</td>
                <td><button class="btn btn-small" data-action="course-invitations" data-id="${escapeHtml(course.id)}">Students</button>
                    ${course.active
                    ? `<button class="btn btn-small btn-danger" data-action="suspend-course" data-id="${escapeHtml(course.id)}" data-name="${escapeHtml(course.name)}">Suspend</button>`
                    : ''}
                    <button class="btn btn-small btn-danger" data-action="delete-course" data-id="${escapeHtml(course.id)}" data-name="${escapeHtml(course.name)}" data-active="${course.active}">Delete</button></td>
            </tr>
            <tr id="course-invitations-${escapeHtml(course.id)}" hidden><td colspan="6"></td></tr>`).join('');
    } catch (e) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty">Failed to load courses</td></tr>';
    }
}

async function deleteCourse(courseId, name, active) {
    const warning = active ? ' It is still running: its students\' tokens stop working at once.' : '';
    if (!confirm(`Delete "${name}" with its tokens, students and invitations?${warning} This cannot be undone.`)) return;
    const response = await fetch(`/api/admin/courses/${encodeURIComponent(courseId)}`, {
        method: 'DELETE', headers: csrfHeaders(),
    });
    if (!response.ok) alert(`Failed to delete course: ${await errorMessage(response)}`);
    loadCourses(coursesPage);
}

async function toggleCourseInvitations(courseId) {
    const row = document.getElementById(`course-invitations-${courseId}`);
    row.hidden = !row.hidden;
    if (row.hidden) return;
    const cell = row.querySelector('td');
    const [seatsResponse, response] = await Promise.all([
        fetch(`/api/admin/courses/${encodeURIComponent(courseId)}/seats`),
        fetch(`/api/admin/courses/${encodeURIComponent(courseId)}/invitations`),
    ]);
    if (!response.ok || !seatsResponse.ok) {
        cell.textContent = `Failed to load students: ${await errorMessage(response.ok ? seatsResponse : response)}`;
        return;
    }
    const seats = await seatsResponse.json();
    const invitations = await response.json();
    const students = seats.length === 0 ? '<p class="muted">Nobody has joined yet.</p>' : `
        <h4>Students</h4>
        <table><thead><tr><th>Student</th><th>Joined</th><th>Via</th><th>Token</th><th>Last used</th><th>Uses</th></tr></thead><tbody>
        ${seats.map(seat => `
            <tr>
                <td>${escapeHtml(seat.student_name)} &lt;${escapeHtml(seat.student_email)}&gt;
                    ${seat.course_user ? '<span class="badge badge-course">Course</span>' : ''}</td>
                <td>${toLocalDateTime(seat.claimed_at)}</td>
                <td>${seat.joined_via === 'invitation' ? 'invitation' : 'shared link'}</td>
                <td>${escapeHtml(seat.token_status)}</td>
                <td>${seat.last_used_at ? toLocalDateTime(seat.last_used_at) : 'Never'}</td>
                <td>${seat.use_count}</td>
            </tr>`).join('')}
        </tbody></table>`;
    cell.innerHTML = students + (invitations.length === 0 ? '' : '<h4>Invitations</h4>') + (invitations.length === 0 ? '' : `
        <table><thead><tr><th>Address</th><th>State</th><th>Token</th><th>Uses</th><th>Link (testing)</th></tr></thead><tbody>
        ${invitations.map(invitation => `
            <tr>
                <td>${escapeHtml(invitation.email)}${invitation.claimed_by_name ? ` (${escapeHtml(invitation.claimed_by_name)})` : ''}</td>
                <td>${invitation.status === 'deleted' ? 'account deleted' : escapeHtml(invitation.status)}${invitation.delivery_failed ? ' (not delivered)' : ''}</td>
                <td>${escapeHtml(invitation.token_status || '')}</td>
                <td>${invitation.use_count}</td>
                <td>${invitation.link ? `<a href="${escapeHtml(invitation.link)}" target="_blank" rel="noopener noreferrer">${escapeHtml(invitation.link)}</a>` : ''}</td>
            </tr>`).join('')}
        </tbody></table>`);
}

async function suspendCourse(courseId, name) {
    if (!confirm(`Suspend "${name}" and revoke all its tokens? This cannot be undone.`)) return;
    const response = await fetch(`/api/admin/courses/${encodeURIComponent(courseId)}/suspend`, {
        method: 'POST', headers: csrfHeaders(),
    });
    if (!response.ok) alert(`Failed to suspend course: ${await errorMessage(response)}`);
    loadCourses(coursesPage);
}

let applicationsPage = 1;

async function loadApplications(page = 1) {
    const tbody = document.getElementById('applicationsTableBody');
    try {
        const params = new URLSearchParams({page, page_size: 100});
        const search = document.getElementById('applicationSearch').value.trim();
        if (search) params.set('q', search);
        const response = await fetch(`/api/admin/applications?${params}`);
        if (!response.ok) throw new Error(await errorMessage(response));
        const applications = await response.json();
        applicationsPage = page;
        document.getElementById('applicationsPrevious').disabled = page <= 1;
        document.getElementById('applicationsNext').disabled = response.headers.get('X-Has-More') !== 'true';
        if (applications.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="empty">${search ? 'No applications match' : 'No applications'}</td></tr>`;
            return;
        }
        tbody.innerHTML = applications.map(application => `
            <tr>
                <td>${escapeHtml(application.name)}${application.description ? `<br><span class="muted">${escapeHtml(application.description)}</span>` : ''}</td>
                <td>${application.orphaned_at
                    ? `<strong>No owner</strong> since ${toLocalDate(application.orphaned_at)}`
                    : application.owners.map(escapeHtml).join('<br>')}</td>
                <td>${application.members}</td>
                <td>${application.tokens} (${application.active_tokens})</td>
                <td>${toLocalDate(application.created_at)}</td>
                <td>${application.orphaned_at ? `
                    <button class="btn btn-small" data-action="take-over-application" data-id="${escapeHtml(application.id)}" data-name="${escapeHtml(application.name)}">Take over</button>
                    <button class="btn btn-small btn-danger" data-action="delete-orphaned-application" data-id="${escapeHtml(application.id)}" data-name="${escapeHtml(application.name)}">Delete</button>` : ''}</td>
            </tr>`).join('');
    } catch (e) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty">Failed to load applications</td></tr>';
    }
}

document.getElementById('applicationSearchForm').addEventListener('submit', (event) => {
    event.preventDefault();
    loadApplications();
});

registerActions({
    'switch-tab': (el) => switchTab(el),
    'applications-previous': () => loadApplications(Math.max(1, applicationsPage - 1)),
    'applications-next': () => loadApplications(applicationsPage + 1),
    'clear-application-search': () => {
        document.getElementById('applicationSearch').value = '';
        loadApplications();
    },
    'toggle-teacher': (el) => toggleTeacher(el.dataset.id, el.dataset.account, el.dataset.teacher === 'true'),
    'suspend-course': (el) => suspendCourse(el.dataset.id, el.dataset.name),
    'course-invitations': (el) => toggleCourseInvitations(el.dataset.id),
    'delete-course': (el) => deleteCourse(el.dataset.id, el.dataset.name, el.dataset.active === 'true'),
    'courses-previous': () => loadCourses(Math.max(1, coursesPage - 1)),
    'courses-next': () => loadCourses(coursesPage + 1),
    'take-over-application': (el) => takeOverApplication(el.dataset.id, el.dataset.name),
    'delete-orphaned-application': (el) => deleteOrphanedApplication(el.dataset.id, el.dataset.name),
    'delete-revoked': () => deleteRevokedTokens(),
    'revoke-token': (el) => revokeToken(el.dataset.id),
    'delete-token': (el) => deleteToken(el.dataset.id),
    'reset-password': (el) => openPasswordModal(el.dataset.id),
    'delete-user': (el) => deleteUser(el.dataset.id, el.dataset.account),
    'toggle-admin': (el) => toggleAdmin(el.dataset.id, el.dataset.account, el.dataset.admin === 'true'),
    'revoke-credentials': (el) => revokeCredentials(el.dataset.id, el.dataset.account),
    'restore-oauth': () => restoreOAuthAccount(),
    'users-previous': () => loadUsers(Math.max(1, usersPage - 1)),
    'users-next': () => loadUsers(usersPage + 1),
    'clear-user-search': () => {
        document.getElementById('userSearch').value = '';
        loadUsers();
    },
    'toggle-password': () => togglePasswordVisibility(),
    'submit-password': () => submitPasswordReset(),
    'close-password': () => closePasswordModal(),
});

document.getElementById('newPasswordInput').addEventListener('keydown', (event) => {
    if (event.key === 'Enter') submitPasswordReset();
});

document.getElementById('userSearchForm').addEventListener('submit', (event) => {
    event.preventDefault();
    loadUsers();
});
