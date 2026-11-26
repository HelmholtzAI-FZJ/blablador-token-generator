// Teacher's course management on the dashboard.

function courseDate(utc) {
    return utc ? new Date(utc).toLocaleDateString() : '';
}

function courseDateTime(utc) {
    return utc ? new Date(utc).toLocaleString() : 'Never';
}

function showCourseLink(url) {
    document.getElementById('courseLinkValue').textContent = url;
    document.getElementById('courseLinkDisplay').hidden = false;
}

function courseState(course) {
    if (course.suspended_at) return `Closed (${escapeHtml(course.suspended_reason || '')})`;
    if (!course.active) return 'Ended';
    return new Date(course.starts_at) > new Date() ? 'Scheduled' : 'Running';
}

async function loadCourses() {
    const list = document.getElementById('coursesList');
    try {
        const response = await fetch('/courses');
        if (!response.ok) throw new Error(await errorMessage(response));
        const courses = await response.json();
        if (courses.length === 0) {
            list.innerHTML = '<p class="empty">No courses yet.</p>';
            return;
        }
        list.innerHTML = `<table><thead><tr><th>Course</th><th>Dates</th><th>Seats</th><th>State</th><th>Actions</th></tr></thead><tbody>
            ${courses.map(course => `
            <tr>
                <td>${escapeHtml(course.name)}</td>
                <td>${courseDate(course.starts_at)} – ${courseDate(new Date(new Date(course.ends_at) - 1).toISOString())}</td>
                <td>${course.seats_claimed} / ${course.max_seats}</td>
                <td>${courseState(course)}</td>
                <td>
                    <button class="btn btn-small" data-action="toggle-seats" data-id="${escapeHtml(course.id)}">Students</button>
                    ${course.active && mailEnabled ? `
                    <button class="btn btn-small" data-action="open-invite" data-id="${escapeHtml(course.id)}" data-name="${escapeHtml(course.name)}">Invite by email</button>` : ''}
                    ${course.active ? `
                    <button class="btn btn-small" data-action="new-course-link" data-id="${escapeHtml(course.id)}">New join link</button>
                    <button class="btn btn-small btn-danger" data-action="close-course" data-id="${escapeHtml(course.id)}" data-name="${escapeHtml(course.name)}">Revoke all and close</button>` : `
                    <button class="btn btn-small btn-danger" data-action="delete-course" data-id="${escapeHtml(course.id)}" data-name="${escapeHtml(course.name)}">Delete</button>`}
                </td>
            </tr>
            <tr class="members-row" id="seats-${escapeHtml(course.id)}" hidden><td colspan="5"><div class="members-panel"></div></td></tr>
            `).join('')}</tbody></table>`;
    } catch (e) {
        list.innerHTML = `<p class="empty">Failed to load courses: ${escapeHtml(e.message)}</p>`;
    }
}

const mailEnabled = document.getElementById('coursesCard').dataset.mail === 'true';

function invitationRows(courseId, invitations) {
    if (invitations.length === 0) return '';
    return `<h4>Invitations</h4>
        <table><thead><tr><th>Address</th><th>State</th><th>Sent</th><th>Token</th><th>Last used</th><th>Uses</th><th></th></tr></thead><tbody>
        ${invitations.map(invitation => `
            <tr>
                <td>${escapeHtml(invitation.email)}${invitation.claimed_by_name ? `<br><span class="muted">signed in as ${escapeHtml(invitation.claimed_by_name)}</span>` : ''}</td>
                <td>${escapeHtml(invitation.status)}${invitation.delivery_failed ? ' <strong>(not delivered)</strong>' : ''}</td>
                <td>${courseDateTime(invitation.sent_at)} (${invitation.send_count}×)</td>
                <td>${escapeHtml(invitation.token_status || '')}</td>
                <td>${invitation.token_status ? courseDateTime(invitation.last_used_at) : ''}</td>
                <td>${invitation.token_status ? invitation.use_count : ''}</td>
                <td>${invitation.status === 'claimed' ? `
                    ${invitation.token_status === 'active' ? `<button class="btn btn-small btn-danger" data-action="revoke-invitation" data-course="${escapeHtml(courseId)}" data-id="${escapeHtml(invitation.id)}" data-email="${escapeHtml(invitation.email)}">Revoke</button>` : ''}
                    <button class="btn btn-small" data-action="reissue-invitation" data-course="${escapeHtml(courseId)}" data-id="${escapeHtml(invitation.id)}" data-email="${escapeHtml(invitation.email)}">Reissue</button>` : ''}
                    ${invitation.status === 'open' ? `
                    <button class="btn btn-small" data-action="resend-invitation" data-course="${escapeHtml(courseId)}" data-id="${escapeHtml(invitation.id)}" data-email="${escapeHtml(invitation.email)}">Resend</button>
                    <button class="btn btn-small btn-danger" data-action="cancel-invitation" data-course="${escapeHtml(courseId)}" data-id="${escapeHtml(invitation.id)}" data-email="${escapeHtml(invitation.email)}">Cancel</button>` : ''}</td>
            </tr>`).join('')}
        </tbody></table>`;
}

async function loadSeats(courseId) {
    const row = document.getElementById(`seats-${courseId}`);
    const panel = row.querySelector('.members-panel');
    const [response, invitationsResponse] = await Promise.all([
        fetch(`/courses/${encodeURIComponent(courseId)}/seats`),
        fetch(`/courses/${encodeURIComponent(courseId)}/invitations`),
    ]);
    if (!response.ok || !invitationsResponse.ok) {
        panel.textContent = `Failed to load students: ${await errorMessage(response.ok ? invitationsResponse : response)}`;
        return;
    }
    const seats = await response.json();
    const invitations = await invitationsResponse.json();
    panel.innerHTML = (seats.length === 0 ? '<p class="muted">Nobody has joined yet.</p>' : `
        <table><thead><tr><th>Student</th><th>Joined</th><th>Token</th><th>Last used</th><th>Uses</th><th></th></tr></thead><tbody>
        ${seats.map(seat => `
            <tr>
                <td>${escapeHtml(seat.student_name)} &lt;${escapeHtml(seat.student_email)}&gt;</td>
                <td>${courseDateTime(seat.claimed_at)}</td>
                <td>${escapeHtml(seat.token_status)}</td>
                <td>${courseDateTime(seat.last_used_at)}</td>
                <td>${seat.use_count}</td>
                <td>${seat.token_status === 'active'
                    ? `<button class="btn btn-small btn-danger" data-action="revoke-seat" data-course="${escapeHtml(courseId)}" data-id="${escapeHtml(seat.id)}" data-name="${escapeHtml(seat.student_name)}">Revoke</button>`
                    : ''}</td>
            </tr>`).join('')}
        </tbody></table>`) + invitationRows(courseId, invitations);
}

function inviteText() {
    return {
        subject: document.getElementById('inviteSubject').value,
        body: document.getElementById('inviteBody').value,
    };
}

document.getElementById('inviteForm')?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const courseId = document.getElementById('inviteCourse').value;
    const emails = document.getElementById('inviteEmails').value.split(/[\s,;]+/).filter(Boolean);
    const response = await fetch(`/courses/${encodeURIComponent(courseId)}/invitations`, {
        method: 'POST',
        headers: csrfHeaders({'Content-Type': 'application/json'}),
        body: JSON.stringify({emails, ...inviteText()}),
    });
    if (!response.ok) {
        alert(`Invitations not sent: ${await errorMessage(response)}`);
        return;
    }
    const result = await response.json();
    let message = `${result.invited.length} invitation(s) sent.`;
    if (result.skipped.length) message += ` Already invited: ${result.skipped.join(', ')}`;
    alert(message);
    document.getElementById('inviteEmails').value = '';
    event.target.hidden = true;
    loadCourses();
});

document.getElementById('createCourseForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    const body = {
        name: document.getElementById('courseName').value,
        starts_on: document.getElementById('courseStarts').value,
        ends_on: document.getElementById('courseEnds').value,
        max_seats: Number(document.getElementById('courseSeats').value),
        accept_terms: document.getElementById('courseTerms').checked,
    };
    const response = await fetch('/courses', {
        method: 'POST',
        headers: csrfHeaders({'Content-Type': 'application/json'}),
        body: JSON.stringify(body),
    });
    if (!response.ok) {
        alert(`Failed to create course: ${await errorMessage(response)}`);
        return;
    }
    const course = await response.json();
    event.target.reset();
    showCourseLink(course.join_url);
    loadCourses();
});

registerActions({
    'open-invite': (el) => {
        const form = document.getElementById('inviteForm');
        document.getElementById('inviteCourse').value = el.dataset.id;
        form.querySelector('h3').textContent = `Invite students to "${el.dataset.name}" by email`;
        form.hidden = false;
        form.scrollIntoView({behavior: 'smooth'});
    },
    'close-invite': () => { document.getElementById('inviteForm').hidden = true; },
    'resend-invitation': async (el) => {
        if (!confirm(`Send ${el.dataset.email} a new link (with the message in the invitation form)? The previous link stops working.`)) return;
        const response = await fetch(
            `/courses/${encodeURIComponent(el.dataset.course)}/invitations/${encodeURIComponent(el.dataset.id)}/resend`,
            {method: 'POST', headers: csrfHeaders({'Content-Type': 'application/json'}), body: JSON.stringify(inviteText())},
        );
        if (!response.ok) alert(`Failed: ${await errorMessage(response)}`);
        loadSeats(el.dataset.course);
    },
    'revoke-invitation': async (el) => {
        if (!confirm(`Revoke the token of ${el.dataset.email}? Their seat stays used.`)) return;
        const response = await fetch(
            `/courses/${encodeURIComponent(el.dataset.course)}/invitations/${encodeURIComponent(el.dataset.id)}/revoke`,
            {method: 'POST', headers: csrfHeaders()},
        );
        if (!response.ok) alert(`Failed: ${await errorMessage(response)}`);
        loadSeats(el.dataset.course);
    },
    'reissue-invitation': async (el) => {
        if (!confirm(`Revoke the token of ${el.dataset.email} and mail them a new link (with the message in the invitation form)?`)) return;
        const response = await fetch(
            `/courses/${encodeURIComponent(el.dataset.course)}/invitations/${encodeURIComponent(el.dataset.id)}/reissue`,
            {method: 'POST', headers: csrfHeaders({'Content-Type': 'application/json'}), body: JSON.stringify(inviteText())},
        );
        if (!response.ok) alert(`Failed: ${await errorMessage(response)}`);
        loadSeats(el.dataset.course);
    },
    'cancel-invitation': async (el) => {
        if (!confirm(`Cancel the invitation of ${el.dataset.email}? Its link stops working and the seat is free again.`)) return;
        const response = await fetch(
            `/courses/${encodeURIComponent(el.dataset.course)}/invitations/${encodeURIComponent(el.dataset.id)}`,
            {method: 'DELETE', headers: csrfHeaders()},
        );
        if (!response.ok) alert(`Failed: ${await errorMessage(response)}`);
        loadSeats(el.dataset.course);
    },
    'toggle-seats': (el) => {
        const row = document.getElementById(`seats-${el.dataset.id}`);
        row.hidden = !row.hidden;
        if (!row.hidden) loadSeats(el.dataset.id);
    },
    'new-course-link': async (el) => {
        if (!confirm('Create a new join link? The current link stops working; students who joined keep their tokens.')) return;
        const response = await fetch(`/courses/${encodeURIComponent(el.dataset.id)}/join-link`, {
            method: 'POST', headers: csrfHeaders(),
        });
        if (!response.ok) {
            alert(`Failed: ${await errorMessage(response)}`);
            return;
        }
        showCourseLink((await response.json()).join_url);
    },
    'close-course': async (el) => {
        if (!confirm(`Revoke every token of "${el.dataset.name}" and close it? This cannot be undone.`)) return;
        const response = await fetch(`/courses/${encodeURIComponent(el.dataset.id)}/close`, {
            method: 'POST', headers: csrfHeaders(),
        });
        if (!response.ok) alert(`Failed: ${await errorMessage(response)}`);
        loadCourses();
    },
    'delete-course': async (el) => {
        if (!confirm(`Delete "${el.dataset.name}" with its students' tokens and invitations? This cannot be undone.`)) return;
        const response = await fetch(`/courses/${encodeURIComponent(el.dataset.id)}`, {
            method: 'DELETE', headers: csrfHeaders(),
        });
        if (!response.ok) alert(`Failed: ${await errorMessage(response)}`);
        loadCourses();
    },
    'revoke-seat': async (el) => {
        if (!confirm(`Revoke the token of ${el.dataset.name}? They cannot join again.`)) return;
        const response = await fetch(
            `/courses/${encodeURIComponent(el.dataset.course)}/seats/${encodeURIComponent(el.dataset.id)}/revoke`,
            {method: 'POST', headers: csrfHeaders()},
        );
        if (!response.ok) alert(`Failed: ${await errorMessage(response)}`);
        loadSeats(el.dataset.course);
    },
    'copy-course-link': async (el) => {
        await navigator.clipboard.writeText(document.getElementById('courseLinkValue').textContent);
        el.textContent = 'Copied';
    },
});

loadCourses();
