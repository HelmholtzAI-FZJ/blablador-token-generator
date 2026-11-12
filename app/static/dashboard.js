
const tokenPolicy = {
    defaultExpirationDays: Number(document.querySelector('meta[name="token-default-expiration-days"]').content),
    maxExpirationDays: Number(document.querySelector('meta[name="token-max-expiration-days"]').content),
};

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

// Display the configured expiration in locale format.
(function() {
    const displayInput = document.getElementById('expiresIn');
    const hiddenInput = document.getElementById('expiresAtRaw');
    
    // Use local date components for the calendar.
    if (!hiddenInput.value) {
        const now = new Date();
        const next = new Date(now.getTime() + tokenPolicy.defaultExpirationDays * 24 * 60 * 60 * 1000);
        const y = next.getFullYear();
        const m = String(next.getMonth() + 1).padStart(2, '0');
        const d = String(next.getDate()).padStart(2, '0');
        hiddenInput.value = y + '-' + m + '-' + d;
        // Display in locale format (use undefined to get browser's default locale)
        displayInput.value = next.toLocaleDateString(undefined, {day: '2-digit', month: '2-digit', year: 'numeric'});
    }
    
    // Create a date picker element
    const pickerContainer = document.createElement('div');
    pickerContainer.id = 'datePickerContainer';
    pickerContainer.style.cssText = 'position: absolute; z-index: 1000; background: white; border: 1px solid #ddd; border-radius: 8px; padding: 10px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); display: none;';
    document.body.appendChild(pickerContainer);
    
    // Build calendar HTML
    const buildCalendar = (currentDate) => {
        const year = currentDate.getFullYear();
        const month = currentDate.getMonth();
        const today = new Date();
        const todayY = today.getFullYear();
        const todayM = today.getMonth();
        const todayD = today.getDate();
        const minDate = new Date(todayY, todayM, todayD + 1);
        const maxDate = new Date(todayY, todayM, todayD + tokenPolicy.maxExpirationDays);
        
        const monthNames = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
        const firstDay = new Date(year, month, 1).getDay();
        const daysInMonth = new Date(year, month + 1, 0).getDate();
        
        let html = '<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">';
        html += '<button type="button" id="prevMonth" style="background:none;border:none;cursor:pointer;font-size:16px;padding:5px;">&#8249;</button>';
        html += '<strong>' + monthNames[month] + ' ' + year + '</strong>';
        html += '<button type="button" id="nextMonth" style="background:none;border:none;cursor:pointer;font-size:16px;padding:5px;">&#8250;</button>';
        html += '</div>';
        
        const dayNames = ['Su', 'Mo', 'Tu', 'We', 'Th', 'Fr', 'Sa'];
        html += '<div style="display: grid; grid-template-columns: repeat(7, 1fr); gap: 2px; text-align: center;">';
        dayNames.forEach(d => html += '<div style="font-size:12px;color:#666;">' + d + '</div>');
        
        for (let i = 0; i < firstDay; i++) html += '<div></div>';
        
        for (let day = 1; day <= daysInMonth; day++) {
            const checkDate = new Date(year, month, day);
            const isDisabled = checkDate < minDate || checkDate > maxDate;
            const isSelected = hiddenInput.value === (year + '-' + String(month + 1).padStart(2, '0') + '-' + String(day).padStart(2, '0'));
            const style = isDisabled ? 'color:#ccc;cursor:not-allowed;' : (isSelected ? 'background:#3498db;color:white;cursor:pointer;border-radius:4px;' : 'cursor:pointer;');
            html += '<div class="day-btn" data-year="' + year + '" data-month="' + month + '" data-day="' + day + '" style="padding:5px;' + style + '">' + day + '</div>';
        }
        html += '</div>';
        pickerContainer.innerHTML = html;
        
        // Event handlers
        const prevBtn = document.getElementById('prevMonth');
        const nextBtn = document.getElementById('nextMonth');
        
        // Check if can go prev (first day of prev month >= today)
        const prevDate = new Date(year, month - 1, 1);
        const canGoPrev = prevDate >= new Date(todayY, todayM, 1);
        prevBtn.style.visibility = canGoPrev ? 'visible' : 'hidden';
        prevBtn.style.cursor = canGoPrev ? 'pointer' : 'default';
        
        // Check if can go next (first day of next month <= 1 year from today)
        const nextDate = new Date(year, month + 1, 1);
        const canGoNext = nextDate <= maxDate;
        nextBtn.style.visibility = canGoNext ? 'visible' : 'hidden';
        nextBtn.style.cursor = canGoNext ? 'pointer' : 'default';
        
        prevBtn.onclick = (e) => { e.stopPropagation(); if (canGoPrev) showCalendar(new Date(year, month - 1, 1)); };
        nextBtn.onclick = (e) => { e.stopPropagation(); if (canGoNext) showCalendar(new Date(year, month + 1, 1)); };
        
        document.querySelectorAll('.day-btn').forEach(btn => {
            btn.onclick = (e) => {
                e.stopPropagation();
                const y = parseInt(btn.dataset.year);
                const m = parseInt(btn.dataset.month);
                const d = parseInt(btn.dataset.day);
                const selected = new Date(y, m, d);
                const y2 = selected.getFullYear();
                const m2 = String(selected.getMonth() + 1).padStart(2, '0');
                const d2 = String(selected.getDate()).padStart(2, '0');
                hiddenInput.value = y2 + '-' + m2 + '-' + d2;
                displayInput.value = selected.toLocaleDateString(undefined, {day: '2-digit', month: '2-digit', year: 'numeric'});
                pickerContainer.style.display = 'none';
            };
        });
    };
    
    const showCalendar = (date) => {
        const rect = displayInput.getBoundingClientRect();
        pickerContainer.style.top = (rect.bottom + window.scrollY + 5) + 'px';
        pickerContainer.style.left = rect.left + 'px';
        buildCalendar(date);
        pickerContainer.style.display = 'block';
    };
    
    displayInput.addEventListener('click', (e) => {
        e.stopPropagation();
        const currentVal = hiddenInput.value;
        let viewDate;
        if (currentVal) {
            const parts = currentVal.split('-');
            viewDate = new Date(parseInt(parts[0]), parseInt(parts[1]) - 1, parseInt(parts[2]));
        } else {
            viewDate = new Date();
        }
        showCalendar(viewDate);
    });
    
    document.addEventListener('click', (e) => {
        if (e.target !== displayInput && !pickerContainer.contains(e.target)) {
            pickerContainer.style.display = 'none';
        }
    });
})();

// Convert all datetime cells to local time
document.querySelectorAll('.datetime').forEach(el => {
    const utc = el.dataset.utc;
    if (utc) {
        const date = new Date(utc);
        if (!isNaN(date)) el.textContent = date.toLocaleString();
    }
});
document.querySelectorAll('.datetime-date').forEach(el => {
    const utc = el.dataset.utc;
    if (utc) {
        const date = new Date(utc);
        if (!isNaN(date)) el.textContent = date.toLocaleDateString();
    }
});

// A new token is shown once; keep it out of a page the browser may restore
// from its back-forward cache.
window.addEventListener('pagehide', () => {
    const value = document.getElementById('newTokenValue');
    if (value) value.textContent = '';
    const display = document.getElementById('newTokenDisplay');
    if (display) display.style.display = 'none';
});

// Set token status (Active/Revoked/Expired)
document.querySelectorAll('.token-status').forEach(el => {
    const isRevoked = el.dataset.revoked === 'true';
    const expiresUtc = el.dataset.expires;
    let status = 'Active';
    if (isRevoked) {
        status = 'Revoked';
    } else if (expiresUtc) {
        const expiresDate = new Date(expiresUtc);
        if (!isNaN(expiresDate) && expiresDate < new Date()) {
            status = 'Expired';
        }
    }
    el.textContent = status;
});

function copyToken() {
    var tokenEl = document.getElementById('newTokenValue');
    if (!tokenEl) {
        alert('No token to copy');
        return;
    }
    var token = tokenEl.textContent || tokenEl.innerText;
    if (!token) {
        alert('No token to copy');
        return;
    }
    
    var btn = document.getElementById('copyBtn');
    
    // Try clipboard API first, fallback to older method
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(token).then(function() {
            btn.innerHTML = '✓ Copied!';
            btn.style.backgroundColor = '#27ae60';
            btn.style.color = 'white';
            setTimeout(function() {
                btn.innerHTML = 'Copy';
                btn.style.backgroundColor = '';
                btn.style.color = '';
            }, 2500);
        })['catch'](function(err) {
            fallbackCopy(token, btn);
        });
    } else {
        fallbackCopy(token, btn);
    }
}

function fallbackCopy(token, btn) {
    // Fallback for older browsers or non-HTTPS
    var textArea = document.createElement('textarea');
    textArea.value = token;
    textArea.style.position = 'fixed';
    textArea.style.left = '-9999px';
    document.body.appendChild(textArea);
    textArea.select();
    try {
        document.execCommand('copy');
        btn.innerHTML = '✓ Copied!';
        btn.style.backgroundColor = '#27ae60';
        btn.style.color = 'white';
        setTimeout(function() {
            btn.innerHTML = 'Copy';
            btn.style.backgroundColor = '';
            btn.style.color = '';
        }, 2500);
    } catch (err) {
        alert('Failed to copy. Please select and copy manually.');
    }
    document.body.removeChild(textArea);
}

function toggleTokenView() {
    const tokenEl = document.getElementById('newTokenValue');
    const hiddenEl = document.getElementById('tokenHidden');
    const viewBtn = document.getElementById('viewBtn');
    
    if (tokenEl.style.display === 'none') {
        tokenEl.style.display = 'inline';
        hiddenEl.style.display = 'none';
        viewBtn.textContent = 'Hide';
    } else {
        tokenEl.style.display = 'none';
        hiddenEl.style.display = 'inline-block';
        viewBtn.textContent = 'View';
    }
}

document.getElementById('createTokenForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const expiresAtRaw = document.getElementById('expiresAtRaw').value;
    const data = {
        name: formData.get('name'),
        expires_at: expiresAtRaw ? new Date(expiresAtRaw + 'T00:00:00').toISOString() : null
    };
    const ownerSelect = document.getElementById('tokenOwner');
    const applicationId = ownerSelect.value;
    const applicationName = applicationId ? ownerSelect.selectedOptions[0].textContent.replace(/^Application: /, '') : '';
    const url = applicationId ? `/applications/${encodeURIComponent(applicationId)}/tokens` : '/tokens';

    const response = await fetch(url, {
        method: 'POST',
        headers: csrfHeaders({'Content-Type': 'application/json'}),
        body: JSON.stringify(data)
    });
    
    if (response.ok) {
        const result = await response.json();
        document.getElementById('newTokenValue').textContent = result.token;
        document.getElementById('newTokenValue').style.display = 'none';
        document.getElementById('tokenHidden').style.display = 'inline-block';
        document.getElementById('viewBtn').textContent = 'View';
        document.getElementById('newTokenDisplay').style.display = 'block';
        e.target.reset();
        
        // Add new token to the table
        const emptyMsg = document.querySelector('.empty');
        let tbody = document.querySelector('table tbody');
        
        // If no table/tbody, create the table structure
        if (!tbody) {
            const tableCard = document.getElementById('tokensCard');
            const tableHtml = `
                <table>
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Belongs to</th>
                            <th>Created</th>
                            <th>Last Used</th>
                            <th>Expires</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody></tbody>
                </table>
            `;
            tableCard.insertAdjacentHTML('beforeend', tableHtml);
            tbody = tableCard.querySelector('table tbody');
            
            if (emptyMsg) emptyMsg.remove();
        }
        
        const now = new Date().toISOString();
        const expires = result.expires_at || '';
        const expiresDisplay = expires ? new Date(expires).toLocaleDateString() : 'Never';
        
        const newRow = document.createElement('tr');
        newRow.dataset.tokenId = result.id;
        newRow.dataset.created = result.created_at;
        newRow.dataset.expires = result.expires_at;
        newRow.innerHTML = `
            <td>${escapeHtml(result.name)}</td>
            <td>${applicationId ? `<span class="app-badge">${escapeHtml(applicationName)}</span>` : '<span class="muted">Personal</span>'}</td>
            <td class="datetime" data-utc="${now}"></td>
            <td class="datetime">Never</td>
            <td class="datetime-date" data-utc="${expires}">${expiresDisplay}</td>
            <td class="token-status" data-revoked="false" data-expires="${expires}">Active</td>
            <td>
                <button class="btn" data-action="rotate-token" data-id="${escapeHtml(result.id)}">Rotate</button>
                <button class="btn btn-danger" data-action="revoke-token" data-id="${escapeHtml(result.id)}">Revoke</button>
                <button class="btn" style="background: #e74c3c;" data-action="delete-token" data-id="${escapeHtml(result.id)}">Delete</button>
            </td>
        `;
        
        // Insert at the top
        const firstRow = tbody.querySelector('tr');
        if (firstRow) {
            tbody.insertBefore(newRow, firstRow);
        } else {
            tbody.appendChild(newRow);
        }
        
        // Convert datetime for new row
        const newDatetime = newRow.querySelector('.datetime');
        if (newDatetime) {
            newDatetime.textContent = new Date(now).toLocaleString();
        }
    } else {
        alert(`Failed to create token: ${await errorMessage(response)}`);
    }
});

document.getElementById('createApplicationForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const description = formData.get('description').trim();
    const response = await fetch('/applications', {
        method: 'POST',
        headers: csrfHeaders({'Content-Type': 'application/json'}),
        body: JSON.stringify({name: formData.get('name'), description: description || null}),
    });
    if (response.ok) {
        location.reload();
    } else {
        alert(`Failed to create application: ${await errorMessage(response)}`);
    }
});

async function deleteApplication(applicationId, name) {
    if (!confirm(`Delete the application "${name}" and all its tokens? This cannot be undone.`)) return;
    const response = await fetch(`/applications/${encodeURIComponent(applicationId)}`, {
        method: 'DELETE',
        headers: csrfHeaders(),
    });
    if (response.ok) {
        location.reload();
    } else {
        alert(`Failed to delete application: ${await errorMessage(response)}`);
    }
}

function membersUrl(applicationId, memberId) {
    const base = `/applications/${encodeURIComponent(applicationId)}/members`;
    return memberId ? `${base}/${encodeURIComponent(memberId)}` : base;
}

async function fetchMembers(applicationId) {
    const response = await fetch(membersUrl(applicationId));
    if (!response.ok) throw new Error(await errorMessage(response));
    return response.json();
}

// The people of an application. Owners see controls to add people by
// email, change roles and remove people; members see the list only.
async function renderMembers(applicationId, isOwner) {
    const panel = document.querySelector(`#members-${CSS.escape(applicationId)} .members-panel`);
    let members;
    try {
        members = await fetchMembers(applicationId);
    } catch (error) {
        panel.innerHTML = `<p class="muted">Could not load people: ${escapeHtml(error.message)}</p>`;
        return;
    }
    const rows = members.map(member => {
        const id = escapeHtml(member.id);
        const label = escapeHtml(member.email) + (member.you ? ' <span class="muted">(you)</span>' : '');
        if (!isOwner) {
            return `<tr><td>${label}</td><td>${member.role === 'owner' ? 'Owner' : 'Member'}</td><td></td></tr>`;
        }
        const options = ['owner', 'member'].map(role =>
            `<option value="${role}"${member.role === role ? ' selected' : ''}>${role === 'owner' ? 'Owner' : 'Member'}</option>`
        ).join('');
        const remove = member.you ? '' :
            `<button class="btn btn-danger btn-small" data-action="remove-member" data-application="${escapeHtml(applicationId)}" data-id="${id}" data-email="${escapeHtml(member.email)}">Remove</button>`;
        return `<tr><td>${label}</td>
            <td><select class="member-role" data-application="${escapeHtml(applicationId)}" data-id="${id}" aria-label="Role of ${escapeHtml(member.email)}">${options}</select></td>
            <td>${remove}</td></tr>`;
    }).join('');
    const form = isOwner ? `
        <form class="member-form" data-application="${escapeHtml(applicationId)}">
            <input type="email" name="email" maxlength="255" placeholder="name@example.org" required aria-label="Email address">
            <select name="role" aria-label="Role">
                <option value="member">Member</option>
                <option value="owner">Owner</option>
            </select>
            <button type="submit" class="btn">Add person</button>
        </form>
        <p class="muted">People who have not signed in yet join when they first sign in with a verified email address.</p>` : '';
    panel.innerHTML = `<table><thead><tr><th>Email</th><th>Role</th><th></th></tr></thead><tbody>${rows}</tbody></table>${form}`;
}

function toggleMembers(element) {
    const row = document.getElementById(`members-${element.dataset.id}`);
    row.hidden = !row.hidden;
    if (!row.hidden) renderMembers(element.dataset.id, element.dataset.role === 'owner');
}

document.addEventListener('submit', async (event) => {
    const form = event.target.closest('.member-form');
    if (!form) return;
    event.preventDefault();
    const applicationId = form.dataset.application;
    const data = new FormData(form);
    const response = await fetch(membersUrl(applicationId), {
        method: 'POST',
        headers: csrfHeaders({'Content-Type': 'application/json'}),
        body: JSON.stringify({email: data.get('email'), role: data.get('role')}),
    });
    if (!response.ok) {
        alert(`Failed to add person: ${await errorMessage(response)}`);
        return;
    }
    renderMembers(applicationId, true);
});

document.addEventListener('change', async (event) => {
    const select = event.target.closest('.member-role');
    if (!select) return;
    const applicationId = select.dataset.application;
    const response = await fetch(membersUrl(applicationId, select.dataset.id), {
        method: 'PATCH',
        headers: csrfHeaders({'Content-Type': 'application/json'}),
        body: JSON.stringify({role: select.value}),
    });
    if (!response.ok) alert(`Failed to change role: ${await errorMessage(response)}`);
    renderMembers(applicationId, true);
});

async function removeMember(applicationId, memberId, email) {
    if (!confirm(`Remove ${email} from this application?`)) return;
    const response = await fetch(membersUrl(applicationId, memberId), {method: 'DELETE', headers: csrfHeaders()});
    if (!response.ok) {
        alert(`Failed to remove person: ${await errorMessage(response)}`);
        return;
    }
    renderMembers(applicationId, true);
}

async function leaveApplication(applicationId, name, role) {
    let members;
    try {
        members = await fetchMembers(applicationId);
    } catch (error) {
        alert(`Failed to leave application: ${error.message}`);
        return;
    }
    const me = members.find(member => member.you);
    const otherOwners = members.some(member => !member.you && member.role === 'owner');
    const warning = role === 'owner' && !otherOwners
        ? `You are the last owner of "${name}". If you leave, it passes to the administrators; its tokens keep working. Leave?`
        : `Leave "${name}"? Its tokens keep working, but you can no longer manage them.`;
    if (!me || !confirm(warning)) return;
    const response = await fetch(membersUrl(applicationId, me.id), {method: 'DELETE', headers: csrfHeaders()});
    if (response.ok) {
        location.reload();
    } else {
        alert(`Failed to leave application: ${await errorMessage(response)}`);
    }
}

async function revokeToken(tokenId) {
    if (!confirm('Are you sure you want to revoke this token?')) return;
    
    const response = await fetch(`/tokens/${tokenId}`, {
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
    const response = await fetch(`/tokens/${tokenId}/permanent`, {
        method: 'DELETE',
        headers: csrfHeaders()
    });
    if (response.ok) {
        location.reload();
    } else {
        alert('Failed to delete token');
    }
}

async function renewToken(tokenId) {
    // POST to renew endpoint; no body means use original duration
    const response = await fetch(`/tokens/${tokenId}/renew`, {
        method: 'POST',
        headers: csrfHeaders()
    });
    if (response.ok) {
        location.reload();
    } else {
        alert('Failed to renew token');
    }
}

// Global variables for renew modal
let currentRenewTokenId = null;
let renewCalendarOpen = false;
let renewModal = null;
let renewModalContent = null;

// Wait for DOM to be ready before creating modal
document.addEventListener('DOMContentLoaded', () => {
    // Create modal elements
    renewModal = document.createElement('div');
    renewModal.id = 'renewModal';
    renewModal.style.cssText = 'display:none;position:fixed;z-index:2000;left:0;top:0;width:100%;height:100%;background:rgba(0,0,0,0.5);';
    document.body.appendChild(renewModal);

    renewModalContent = document.createElement('div');
    renewModalContent.style.cssText = 'background:white;margin:10% auto;padding:20px;width:320px;border-radius:8px;box-shadow:0 4px 20px rgba(0,0,0,0.3);position:relative;';
    renewModal.appendChild(renewModalContent);

    const renewModalHTML = `
        <h3 style="margin-top:0;">Renew Token</h3>
        <p style="margin-bottom:10px;">Select new expiration date:</p>
        <div style="margin-bottom:15px;">
            <label for="renewExpiresDisplay" style="display:block;margin-bottom:5px;">Expires on</label>
            <input type="text" id="renewExpiresDisplay" placeholder="DD/MM/YYYY" readonly style="padding:0.5rem;border:1px solid #ddd;border-radius:4px;width:100%;background:#f8f9fa;">
            <input type="hidden" id="renewExpiresAtRaw">
        </div>
        <div id="renewCalendarContainer" style="background:#f8f9fa;padding:10px;border-radius:4px;margin-bottom:15px;">
            <div style="text-align:center;font-weight:bold;margin-bottom:10px;color:#333;">Select Expiration Date</div>
        </div>
        <div style="display:flex;justify-content:flex-end;gap:10px;">
            <button id="renewCancelBtn" style="padding:0.5rem 1rem;border:1px solid #ddd;border-radius:4px;background:white;cursor:pointer;">Cancel</button>
            <button id="renewConfirmBtn" style="padding:0.5rem 1rem;border:none;border-radius:4px;background:#2ecc71;color:white;cursor:pointer;">Renew</button>
        </div>
    `;
    renewModalContent.innerHTML = renewModalHTML;

    // Set up button event listeners
    document.getElementById('renewCancelBtn').onclick = () => {
        renewModal.style.display = 'none';
        renewCalendarOpen = false;
        currentRenewTokenId = null;
    };

    document.getElementById('renewConfirmBtn').onclick = async () => {
        const expiresAtRaw = document.getElementById('renewExpiresAtRaw').value;
        if (!expiresAtRaw) {
            alert('Please select a date');
            return;
        }
        const expiresAt = new Date(expiresAtRaw + 'T00:00:00').toISOString();
        const response = await fetch(`/tokens/${currentRenewTokenId}/renew`, {
            method: 'POST',
            headers: csrfHeaders({'Content-Type': 'application/json'}),
            body: JSON.stringify({ expires_at: expiresAt })
        });
        if (response.ok) {
            location.reload();
        } else {
            alert('Failed to renew token');
        }
    };

    // Define showRenewCalendar inside to access modal elements
    window.showRenewCalendar = (currentDate) => {
        const year = currentDate.getFullYear();
        const month = currentDate.getMonth();
        const today = new Date();
        const todayY = today.getFullYear();
        const todayM = today.getMonth();
        const todayD = today.getDate();
        const minDate = new Date(todayY, todayM, todayD + 1);
        const maxDate = new Date(todayY, todayM, todayD + tokenPolicy.maxExpirationDays);

        const monthNames = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
        const firstDay = new Date(year, month, 1).getDay();
        const daysInMonth = new Date(year, month + 1, 0).getDate();

        let html = '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">';
        html += '<button type="button" id="renewPrevMonth" style="background:none;border:none;cursor:pointer;font-size:16px;padding:5px;">&#8249;</button>';
        html += '<strong>' + monthNames[month] + ' ' + year + '</strong>';
        html += '<button type="button" id="renewNextMonth" style="background:none;border:none;cursor:pointer;font-size:16px;padding:5px;">&#8250;</button>';
        html += '</div>';

        const dayNames = ['Su', 'Mo', 'Tu', 'We', 'Th', 'Fr', 'Sa'];
        html += '<div style="display:grid;grid-template-columns:repeat(7,1fr);gap:2px;text-align:center;">';
        dayNames.forEach(d => html += '<div style="font-size:12px;color:#666;">' + d + '</div>');

        for (let i = 0; i < firstDay; i++) html += '<div></div>';

        for (let day = 1; day <= daysInMonth; day++) {
            const checkDate = new Date(year, month, day);
            const isDisabled = checkDate < minDate || checkDate > maxDate;
            const isSelected = document.getElementById('renewExpiresAtRaw').value === (year + '-' + String(month + 1).padStart(2, '0') + '-' + String(day).padStart(2, '0'));
            const style = isDisabled ? 'color:#ccc;cursor:not-allowed;' : (isSelected ? 'background:#3498db;color:white;cursor:pointer;border-radius:4px;' : 'cursor:pointer;');
            html += '<div class="renew-day-btn" data-year="' + year + '" data-month="' + month + '" data-day="' + day + '" style="padding:5px;' + style + '">' + day + '</div>';
        }
        html += '</div>';
        document.getElementById('renewCalendarContainer').innerHTML = html;

        const prevBtn = document.getElementById('renewPrevMonth');
        const nextBtn = document.getElementById('renewNextMonth');

        const prevDate = new Date(year, month - 1, 1);
        const canGoPrev = prevDate >= new Date(todayY, todayM, 1);
        prevBtn.style.visibility = canGoPrev ? 'visible' : 'hidden';
        prevBtn.style.cursor = canGoPrev ? 'pointer' : 'default';

        const nextDate = new Date(year, month + 1, 1);
        const canGoNext = nextDate <= maxDate;
        nextBtn.style.visibility = canGoNext ? 'visible' : 'hidden';
        nextBtn.style.cursor = canGoNext ? 'pointer' : 'default';

        prevBtn.onclick = (e) => { e.stopPropagation(); if (canGoPrev) window.showRenewCalendar(new Date(year, month - 1, 1)); };
        nextBtn.onclick = (e) => { e.stopPropagation(); if (canGoNext) window.showRenewCalendar(new Date(year, month + 1, 1)); };

        document.querySelectorAll('.renew-day-btn').forEach(btn => {
            btn.onclick = (e) => {
                e.stopPropagation();
                const y = parseInt(btn.dataset.year);
                const m = parseInt(btn.dataset.month);
                const d = parseInt(btn.dataset.day);
                const selected = new Date(y, m, d);
                const yStr = String(y);
                const mStr = String(m + 1).padStart(2, '0');
                const dStr = String(d).padStart(2, '0');
                document.getElementById('renewExpiresAtRaw').value = yStr + '-' + mStr + '-' + dStr;
                document.getElementById('renewExpiresDisplay').value = selected.toLocaleDateString(undefined, {day: '2-digit', month: '2-digit', year: 'numeric'});
                window.showRenewCalendar(new Date(y, m, 1));
            };
        });
    };

    // Define openRenewModal
    window.openRenewModal = (tokenId) => {
        const row = document.querySelector(`tr[data-token-id="${tokenId}"]`);
        if (!row) return;
        const createdIso = row.dataset.created;
        const expiresIso = row.dataset.expires;

        currentRenewTokenId = tokenId;

        // Compute original duration
        let defaultDate;
        if (createdIso && expiresIso) {
            const created = new Date(createdIso);
            const expires = new Date(expiresIso);
            const durationMs = expires - created;
            const durationDays = Math.ceil(durationMs / (1000 * 60 * 60 * 24));
            const now = new Date();
            defaultDate = new Date(now.getFullYear(), now.getMonth(), now.getDate() + durationDays);
        } else {
            // Fallback: 1 month
            defaultDate = new Date(new Date().getFullYear(), new Date().getMonth() + 1, new Date().getDate());
        }

        const y = defaultDate.getFullYear();
        const m = String(defaultDate.getMonth() + 1).padStart(2, '0');
        const d = String(defaultDate.getDate()).padStart(2, '0');
        document.getElementById('renewExpiresAtRaw').value = y + '-' + m + '-' + d;
        document.getElementById('renewExpiresDisplay').value = defaultDate.toLocaleDateString(undefined, {day: '2-digit', month: '2-digit', year: 'numeric'});

        // Show calendar immediately
        window.showRenewCalendar(defaultDate);

        renewModal.style.display = 'block';
        renewCalendarOpen = true;
        
        // Focus on the first button for accessibility
        setTimeout(() => {
            const confirmBtn = document.getElementById('renewConfirmBtn');
            if (confirmBtn) confirmBtn.focus();
        }, 100);
    };
});

async function rotateToken(tokenId) {
    if (!confirm('Replace this token? Its current value will stop working immediately.')) return;
    try {
        const response = await fetch(`/tokens/${encodeURIComponent(tokenId)}/rotate`, {
            method: 'POST', headers: csrfHeaders(),
        });
        if (!response.ok) {
            const error = await response.json();
            throw new Error(typeof error.detail === 'string' ? error.detail : 'Rotation failed');
        }
        const result = await response.json();
        document.getElementById('newTokenValue').textContent = result.token;
        document.getElementById('newTokenValue').style.display = 'none';
        document.getElementById('tokenHidden').style.display = 'inline-block';
        document.getElementById('viewBtn').textContent = 'View';
        document.getElementById('newTokenDisplay').style.display = 'block';
        document.getElementById('newTokenDisplay').scrollIntoView({block: 'center'});
    } catch (error) {
        alert('Failed to rotate token: ' + error.message);
    }
}

async function revokeAllCredentials() {
    if (!confirm('Revoke every API token and sign out all of your browser sessions?')) return;
    try {
        const response = await fetch('/tokens/revoke-all', {method: 'POST', headers: csrfHeaders()});
        if (!response.ok) throw new Error('Revocation failed');
        window.location.href = '/';
    } catch {
        alert('Credential revocation could not be completed. Please retry.');
    }
}

registerActions({
    'toggle-token-view': () => toggleTokenView(),
    'copy-token': () => copyToken(),
    'revoke-token': (el) => revokeToken(el.dataset.id),
    'delete-token': (el) => deleteToken(el.dataset.id),
    'renew-token': (el) => window.openRenewModal(el.dataset.id),
    'rotate-token': (el) => rotateToken(el.dataset.id),
    'revoke-all': () => revokeAllCredentials(),
    'delete-application': (el) => deleteApplication(el.dataset.id, el.dataset.name),
    'toggle-members': (el) => toggleMembers(el),
    'leave-application': (el) => leaveApplication(el.dataset.id, el.dataset.name, el.dataset.role),
    'remove-member': (el) => removeMember(el.dataset.application, el.dataset.id, el.dataset.email),
});
