document.querySelectorAll('.datetime-date').forEach(el => {
    if (el.dataset.utc) el.textContent = new Date(el.dataset.utc).toLocaleDateString();
});

registerActions({
    'join-course': async (el) => {
        el.disabled = true;
        const error = document.getElementById('joinError');
        error.textContent = '';
        try {
            const response = await fetch(el.dataset.path, {
                method: 'POST', headers: csrfHeaders(),
            });
            if (!response.ok) throw new Error(await errorMessage(response));
            const result = await response.json();
            document.getElementById('courseTokenValue').textContent = result.token;
            document.getElementById('courseTokenCurl').textContent = curlTest(result.token);
            document.getElementById('joinArea').hidden = true;
            document.getElementById('joinResult').hidden = false;
            document.querySelector('#joinResult .token-alert').scrollIntoView({behavior: 'smooth', block: 'center'});
        } catch (e) {
            error.textContent = e.message;
            el.disabled = false;
        }
    },
    'copy-course-token': (el) => copyText(document.getElementById('courseTokenValue').textContent, el),
    'copy-course-curl': (el) => copyText(document.getElementById('courseTokenCurl').textContent, el),
});
