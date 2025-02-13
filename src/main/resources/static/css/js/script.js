function switchTab(tab) {
    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');
    const tabs = document.querySelectorAll('.tab');

    tabs.forEach(t => t.classList.remove('active'));

    if (tab === 'login') {
        loginForm.style.display = 'block';
        registerForm.style.display = 'none';
        tabs[0].classList.add('active');
    } else {
        loginForm.style.display = 'none';
        registerForm.style.display = 'block';
        tabs[1].classList.add('active');
    }
}

// Handle form validation messages fade out
document.addEventListener('DOMContentLoaded', function() {
    const messages = document.querySelectorAll('.error-message, .success-message');
    messages.forEach(message => {
        setTimeout(() => {
            message.style.opacity = '0';
            setTimeout(() => message.style.display = 'none', 600);
        }, 5000);
    });
});

// Add password validation
document.querySelectorAll('form').forEach(form => {
    form.addEventListener('submit', function(e) {
        const password = form.querySelector('input[type="password"]');
        const confirmPassword = form.querySelector('input[name="confirmPassword"]');

        if (confirmPassword && password.value !== confirmPassword.value) {
            e.preventDefault();
            const errorDiv = document.createElement('div');
            errorDiv.className = 'error-message';
            errorDiv.textContent = 'Passwords do not match';
            confirmPassword.parentNode.appendChild(errorDiv);
        }
    });
});