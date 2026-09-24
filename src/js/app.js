// Secure Password Manager - Interactive Frontend Engine
document.addEventListener('DOMContentLoaded', () => {

    // 1. Auto-dismiss flash notification alerts after 5 seconds
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

    // 2. Real-Time Master Password Strength Indicator (Register Form)
    const masterPassInput = document.getElementById('master_password');
    const strengthBar = document.getElementById('strengthBar');
    const strengthText = document.getElementById('strengthText');

    if (masterPassInput && strengthBar && strengthText) {
        masterPassInput.addEventListener('input', () => {
            const pwd = masterPassInput.value;
            if (!pwd) {
                strengthBar.style.width = '0%';
                strengthText.innerText = 'Password strength';
                return;
            }

            let score = 0;
            if (pwd.length >= 8) score += 20;
            if (pwd.length >= 12) score += 20;
            if (/[A-Z]/.test(pwd)) score += 20;
            if (/[0-9]/.test(pwd)) score += 20;
            if (/[^A-Za-z0-9]/.test(pwd)) score += 20;

            strengthBar.style.width = score + '%';
            if (score <= 40) {
                strengthBar.style.backgroundColor = '#f43f5e';
                strengthText.innerText = 'Strength: Weak';
                strengthText.style.color = '#f43f5e';
            } else if (score <= 60) {
                strengthBar.style.backgroundColor = '#f59e0b';
                strengthText.innerText = 'Strength: Moderate';
                strengthText.style.color = '#f59e0b';
            } else if (score <= 80) {
                strengthBar.style.backgroundColor = '#06b6d4';
                strengthText.innerText = 'Strength: Strong';
                strengthText.style.color = '#06b6d4';
            } else {
                strengthBar.style.backgroundColor = '#10b981';
                strengthText.innerText = 'Strength: Very Strong (Optimal)';
                strengthText.style.color = '#10b981';
            }
        });
    }

    // 3. Vault Entry Decryption & Reveal / Copy
    document.querySelectorAll('.btn-reveal').forEach(btn => {
        btn.addEventListener('click', async () => {
            const entryId = btn.getAttribute('data-id');
            const inputField = document.getElementById(`pwd-${entryId}`);
            
            if (inputField.type === 'password') {
                try {
                    btn.innerText = '⏳';
                    const response = await fetch(`/api/vault/decrypt/${entryId}`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' }
                    });
                    const data = await response.json();
                    if (data.success) {
                        inputField.value = data.password;
                        inputField.type = 'text';
                        btn.innerText = '🙈';
                        btn.title = 'Hide Password';
                    } else {
                        alert(data.error || 'Failed to decrypt credential.');
                        btn.innerText = '👁️';
                    }
                } catch (err) {
                    alert('Network or server error during decryption.');
                    btn.innerText = '👁️';
                }
            } else {
                inputField.type = 'password';
                inputField.value = '••••••••••••••••';
                btn.innerText = '👁️';
                btn.title = 'Reveal Password';
            }
        });
    });

    // 4. Quick Copy Credential to Clipboard
    document.querySelectorAll('.btn-copy').forEach(btn => {
        btn.addEventListener('click', async () => {
            const entryId = btn.getAttribute('data-id');
            const inputField = document.getElementById(`pwd-${entryId}`);
            
            try {
                let textToCopy = inputField.value;
                if (inputField.type === 'password' || textToCopy.startsWith('•••')) {
                    const response = await fetch(`/api/vault/decrypt/${entryId}`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' }
                    });
                    const data = await response.json();
                    if (data.success) {
                        textToCopy = data.password;
                    } else {
                        alert('Could not decrypt password for copying.');
                        return;
                    }
                }
                
                await navigator.clipboard.writeText(textToCopy);
                const originalText = btn.innerText;
                btn.innerText = '✅';
                setTimeout(() => { btn.innerText = originalText; }, 1500);
            } catch (err) {
                alert('Failed to copy to clipboard.');
            }
        });
    });

    // 5. Credential Add & Edit Modal Handling
    const credentialModal = document.getElementById('credentialModal');
    const openAddModalBtn = document.getElementById('openAddModalBtn');
    const openAddEmptyBtn = document.getElementById('openAddEmptyBtn');
    const closeModalBtn = document.getElementById('closeModalBtn');
    const cancelModalBtn = document.getElementById('cancelModalBtn');
    const credentialForm = document.getElementById('credentialForm');
    const modalTitle = document.getElementById('modalTitle');
    const formTitle = document.getElementById('form_title');
    const formUsername = document.getElementById('form_username');
    const formCategory = document.getElementById('form_category');
    const formPassword = document.getElementById('form_password');
    const formUrl = document.getElementById('form_url');
    const formNotes = document.getElementById('form_notes');

    function openAddModal() {
        if (!credentialModal) return;
        modalTitle.innerText = 'Add New Credential';
        credentialForm.action = '/vault/add';
        credentialForm.reset();
        formPassword.required = true;
        formPassword.placeholder = 'Enter secure password';
        credentialModal.style.display = 'flex';
    }

    if (openAddModalBtn) openAddModalBtn.addEventListener('click', openAddModal);
    if (openAddEmptyBtn) openAddEmptyBtn.addEventListener('click', openAddModal);

    function closeModal() {
        if (credentialModal) credentialModal.style.display = 'none';
    }

    if (closeModalBtn) closeModalBtn.addEventListener('click', closeModal);
    if (cancelModalBtn) cancelModalBtn.addEventListener('click', closeModal);

    // Edit button clicks
    document.querySelectorAll('.btn-edit').forEach(btn => {
        btn.addEventListener('click', () => {
            const entryId = btn.getAttribute('data-id');
            modalTitle.innerText = 'Edit Credential';
            credentialForm.action = `/vault/update/${entryId}`;
            
            formTitle.value = btn.getAttribute('data-title') || '';
            formUsername.value = btn.getAttribute('data-username') || '';
            formCategory.value = btn.getAttribute('data-category') || 'General';
            formUrl.value = btn.getAttribute('data-url') || '';
            formNotes.value = btn.getAttribute('data-notes') || '';
            
            formPassword.value = '';
            formPassword.required = false;
            formPassword.placeholder = 'Leave blank to keep current password';
            
            credentialModal.style.display = 'flex';
        });
    });

    // 6. CSPRNG Password Generator Modal Handling
    const generatorModal = document.getElementById('generatorModal');
    const openGenBtn = document.getElementById('openGenBtn');
    const closeGenModalBtn = document.getElementById('closeGenModalBtn');
    const regenerateBtn = document.getElementById('regenerateBtn');
    const genLengthSlider = document.getElementById('genLengthSlider');
    const genLengthVal = document.getElementById('genLengthVal');
    const genResultText = document.getElementById('genResultText');
    const genEntropyText = document.getElementById('genEntropyText');
    const genRatingBadge = document.getElementById('genRatingBadge');
    const genStrengthBar = document.getElementById('genStrengthBar');
    const copyGenBtn = document.getElementById('copyGenBtn');
    const useGenPasswordBtn = document.getElementById('useGenPasswordBtn');
    const generateInModalBtn = document.getElementById('generateInModalBtn');

    let currentGeneratedPassword = '';

    async function fetchGeneratedPassword() {
        if (!genLengthSlider) return;
        const length = parseInt(genLengthSlider.value, 10);
        const use_upper = document.getElementById('genUpper')?.checked ?? true;
        const use_lower = document.getElementById('genLower')?.checked ?? true;
        const use_digits = document.getElementById('genDigits')?.checked ?? true;
        const use_symbols = document.getElementById('genSymbols')?.checked ?? true;

        try {
            const res = await fetch('/api/password/generate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ length, use_upper, use_lower, use_digits, use_symbols })
            });
            const data = await res.json();
            if (data.success) {
                currentGeneratedPassword = data.password;
                genResultText.innerText = data.password;
                genEntropyText.innerText = `Entropy: ${data.strength.entropy} bits`;
                genRatingBadge.innerText = data.strength.rating;
                genStrengthBar.style.width = `${data.strength.score}%`;

                if (data.strength.score >= 80) {
                    genStrengthBar.style.backgroundColor = '#10b981';
                    genRatingBadge.style.backgroundColor = '#10b981';
                } else if (data.strength.score >= 60) {
                    genStrengthBar.style.backgroundColor = '#06b6d4';
                    genRatingBadge.style.backgroundColor = '#06b6d4';
                } else {
                    genStrengthBar.style.backgroundColor = '#f59e0b';
                    genRatingBadge.style.backgroundColor = '#f59e0b';
                }
            }
        } catch (err) {
            genResultText.innerText = 'Error generating key';
        }
    }

    if (openGenBtn && generatorModal) {
        openGenBtn.addEventListener('click', () => {
            generatorModal.style.display = 'flex';
            fetchGeneratedPassword();
        });
    }

    if (closeGenModalBtn && generatorModal) {
        closeGenModalBtn.addEventListener('click', () => {
            generatorModal.style.display = 'none';
        });
    }

    if (genLengthSlider && genLengthVal) {
        genLengthSlider.addEventListener('input', () => {
            genLengthVal.innerText = genLengthSlider.value;
            fetchGeneratedPassword();
        });
    }

    ['genUpper', 'genLower', 'genDigits', 'genSymbols'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.addEventListener('change', fetchGeneratedPassword);
    });

    if (regenerateBtn) regenerateBtn.addEventListener('click', fetchGeneratedPassword);

    if (copyGenBtn) {
        copyGenBtn.addEventListener('click', async () => {
            if (!currentGeneratedPassword) return;
            await navigator.clipboard.writeText(currentGeneratedPassword);
            const original = copyGenBtn.innerText;
            copyGenBtn.innerText = '✅';
            setTimeout(() => { copyGenBtn.innerText = original; }, 1500);
        });
    }

    if (useGenPasswordBtn) {
        useGenPasswordBtn.addEventListener('click', () => {
            if (formPassword && currentGeneratedPassword) {
                formPassword.value = currentGeneratedPassword;
                formPassword.type = 'text';
            }
            if (generatorModal) generatorModal.style.display = 'none';
        });
    }

    if (generateInModalBtn) {
        generateInModalBtn.addEventListener('click', () => {
            if (generatorModal) {
                generatorModal.style.display = 'flex';
                fetchGeneratedPassword();
            }
        });
    }
});
