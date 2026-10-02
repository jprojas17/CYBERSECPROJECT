// Secure Password Manager - Core Frontend Controller
document.addEventListener('DOMContentLoaded', () => {
    const csrfToken = document.querySelector('input[name="csrf_token"]')?.value || '';

    // Toast notification helper
    function showToast(message) {
        const toast = document.getElementById('toast');
        if (toast) {
            toast.textContent = message;
            toast.classList.remove('hidden');
            toast.style.opacity = '1';
            setTimeout(() => {
                toast.style.opacity = '0';
                setTimeout(() => toast.classList.add('hidden'), 300);
            }, 2500);
        }
    }

    // Auto-dismiss flash notifications
    const flashMessages = document.querySelectorAll('.flash-msg');
    if (flashMessages.length > 0) {
        setTimeout(() => {
            flashMessages.forEach(msg => {
                msg.style.transition = 'opacity 0.5s ease';
                msg.style.opacity = '0';
                setTimeout(() => msg.remove(), 500);
            });
        }, 5000);
    }

    // Modal helpers
    function openModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) modal.classList.remove('hidden');
    }

    function closeModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) modal.classList.add('hidden');
    }

    // Add Credential Modal
    document.getElementById('btn-open-add-modal')?.addEventListener('click', () => openModal('add-modal'));
    document.getElementById('btn-empty-add')?.addEventListener('click', () => openModal('add-modal'));
    document.getElementById('btn-close-add')?.addEventListener('click', () => closeModal('add-modal'));
    document.getElementById('btn-cancel-add')?.addEventListener('click', () => closeModal('add-modal'));

    // Edit Credential Modal
    document.querySelectorAll('.btn-edit').forEach(btn => {
        btn.addEventListener('click', () => {
            const id = btn.dataset.id;
            const service = btn.dataset.service;
            const username = btn.dataset.username;
            const notes = btn.dataset.notes;

            const editForm = document.getElementById('edit-form');
            if (editForm) {
                editForm.action = `/vault/edit/${id}`;
                document.getElementById('edit_service').value = service || '';
                document.getElementById('edit_username').value = username || '';
                document.getElementById('edit_notes').value = notes || '';
                document.getElementById('edit_password').value = '';
                openModal('edit-modal');
            }
        });
    });

    document.getElementById('btn-close-edit')?.addEventListener('click', () => closeModal('edit-modal'));
    document.getElementById('btn-cancel-edit')?.addEventListener('click', () => closeModal('edit-modal'));

    // Password Generator Modal & Logic
    const generatorModal = document.getElementById('generator-modal');
    const genLengthSlider = document.getElementById('gen-length');
    const genLengthVal = document.getElementById('gen-length-val');
    const genUpper = document.getElementById('gen-upper');
    const genLower = document.getElementById('gen-lower');
    const genDigits = document.getElementById('gen-digits');
    const genSymbols = document.getElementById('gen-symbols');
    const genPasswordDisplay = document.getElementById('gen-password-display');
    const strengthBar = document.getElementById('strength-bar');
    const strengthRating = document.getElementById('strength-rating');
    const strengthEntropy = document.getElementById('strength-entropy');

    async function fetchGeneratedPassword() {
        if (!genLengthSlider) return;
        try {
            const response = await fetch('/api/generate-password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify({
                    length: parseInt(genLengthSlider.value, 10),
                    upper: genUpper.checked,
                    lower: genLower.checked,
                    digits: genDigits.checked,
                    symbols: genSymbols.checked
                })
            });

            const data = await response.json();
            if (data.success) {
                genPasswordDisplay.value = data.password;
                updateStrengthUI(data.analysis);
            }
        } catch (err) {
            console.error('Password generator error:', err);
        }
    }

    function updateStrengthUI(analysis) {
        if (!analysis || !strengthBar) return;
        strengthBar.style.width = `${analysis.score}%`;
        strengthEntropy.textContent = `Entropy: ${analysis.entropy} bits`;
        strengthRating.textContent = `Strength: ${analysis.rating}`;

        if (analysis.score < 50) {
            strengthBar.style.backgroundColor = '#f43f5e';
        } else if (analysis.score < 80) {
            strengthBar.style.backgroundColor = '#f59e0b';
        } else {
            strengthBar.style.backgroundColor = '#10b981';
        }
    }

    if (genLengthSlider) {
        genLengthSlider.addEventListener('input', (e) => {
            genLengthVal.textContent = e.target.value;
            fetchGeneratedPassword();
        });
        [genUpper, genLower, genDigits, genSymbols].forEach(cb => {
            cb?.addEventListener('change', fetchGeneratedPassword);
        });
    }

    document.getElementById('btn-open-generator')?.addEventListener('click', () => {
        openModal('generator-modal');
        fetchGeneratedPassword();
    });

    document.getElementById('btn-gen-into-add')?.addEventListener('click', () => {
        openModal('generator-modal');
        fetchGeneratedPassword();
    });

    document.getElementById('btn-close-generator')?.addEventListener('click', () => closeModal('generator-modal'));
    document.getElementById('btn-regenerate')?.addEventListener('click', fetchGeneratedPassword);

    document.getElementById('btn-copy-generated')?.addEventListener('click', () => {
        if (genPasswordDisplay.value) {
            navigator.clipboard.writeText(genPasswordDisplay.value);
            showToast('Generated password copied to clipboard!');
        }
    });

    document.getElementById('btn-use-password')?.addEventListener('click', () => {
        const addPwInput = document.getElementById('add_password');
        if (addPwInput && genPasswordDisplay.value) {
            addPwInput.value = genPasswordDisplay.value;
            closeModal('generator-modal');
            openModal('add-modal');
            showToast('Password applied to Add form.');
        }
    });

    // Vault search filtering
    const searchInput = document.getElementById('vault-search');
    searchInput?.addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase().trim();
        const cards = document.querySelectorAll('.vault-card');
        cards.forEach(card => {
            const service = card.dataset.service || '';
            const username = card.dataset.username || '';
            const notes = card.dataset.notes || '';
            const matches = service.includes(query) || username.includes(query) || notes.includes(query);
            card.style.display = matches ? 'flex' : 'none';
        });
    });

    // On-Demand Decryption & Auto-Masking Timer
    const timers = {};

    document.querySelectorAll('.btn-reveal').forEach(btn => {
        btn.addEventListener('click', async () => {
            const id = btn.dataset.id;
            const maskEl = document.getElementById(`pw-mask-${id}`);
            const plainEl = document.getElementById(`pw-plain-${id}`);
            const copyBtn = document.getElementById(`btn-copy-${id}`);
            const timerEl = document.getElementById(`timer-${id}`);

            // Toggle back to masked if already revealed
            if (!plainEl.classList.contains('hidden')) {
                plainEl.classList.add('hidden');
                maskEl.classList.remove('hidden');
                copyBtn.classList.add('hidden');
                timerEl.classList.add('hidden');
                btn.textContent = 'Reveal';
                if (timers[id]) clearInterval(timers[id]);
                return;
            }

            btn.disabled = true;
            btn.textContent = 'Decrypting...';

            try {
                const formData = new FormData();
                formData.append('csrf_token', csrfToken);

                const response = await fetch(`/vault/decrypt/${id}`, {
                    method: 'POST',
                    headers: { 'X-CSRF-Token': csrfToken },
                    body: formData
                });

                const data = await response.json();
                if (data.success) {
                    plainEl.textContent = data.password;
                    plainEl.classList.remove('hidden');
                    maskEl.classList.add('hidden');
                    copyBtn.classList.remove('hidden');
                    timerEl.classList.remove('hidden');
                    btn.textContent = 'Hide';

                    // 15 seconds countdown
                    let timeLeft = 15;
                    timerEl.textContent = `Auto-hiding in ${timeLeft}s`;

                    if (timers[id]) clearInterval(timers[id]);
                    timers[id] = setInterval(() => {
                        timeLeft -= 1;
                        if (timeLeft <= 0) {
                            clearInterval(timers[id]);
                            plainEl.classList.add('hidden');
                            maskEl.classList.remove('hidden');
                            copyBtn.classList.add('hidden');
                            timerEl.classList.add('hidden');
                            btn.textContent = 'Reveal';
                        } else {
                            timerEl.textContent = `Auto-hiding in ${timeLeft}s`;
                        }
                    }, 1000);
                } else {
                    showToast('Decryption error: ' + (data.error || 'Unauthorized'));
                    btn.textContent = 'Reveal';
                }
            } catch (err) {
                console.error(err);
                showToast('Failed to connect to decryption service.');
                btn.textContent = 'Reveal';
            } finally {
                btn.disabled = false;
            }
        });
    });

    // Copy decrypted password
    document.querySelectorAll('.btn-copy').forEach(btn => {
        btn.addEventListener('click', () => {
            const id = btn.dataset.id;
            const plainEl = document.getElementById(`pw-plain-${id}`);
            if (plainEl && plainEl.textContent) {
                navigator.clipboard.writeText(plainEl.textContent);
                showToast('Password copied to clipboard!');
            }
        });
    });
});
