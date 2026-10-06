document.addEventListener('DOMContentLoaded', () => {
    const formLogin = document.getElementById('formLogin');
    const authAlert = document.getElementById('authAlert');

    if (!formLogin) return;

    formLogin.addEventListener('submit', async (e) => {
        e.preventDefault();

        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value.trim();

        if (!username || !password) {
            showAlert('Preencha todos os campos.', 'danger');
            return;
        }

        showAlert('Autenticando...', 'info');

        try {
            const res = await fetch('/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });

            const data = await res.json();

            if (res.ok) {
                showAlert('Login efetuado com sucesso! Redirecionando...', 'success');
                
                // Armazena credenciais
                localStorage.setItem('token', data.token);
                localStorage.setItem('username', data.username);
                localStorage.setItem('role', data.role);

                setTimeout(() => {
                    window.location.href = '/';
                }, 800);
            } else {
                showAlert(data.erro || 'Credenciais inválidas.', 'danger');
            }
        } catch (err) {
            console.error('Erro na conexão:', err);
            showAlert('Não foi possível se conectar ao servidor.', 'danger');
        }
    });

    function showAlert(msg, type) {
        authAlert.innerText = msg;
        authAlert.className = `auth-alert ${type}`;
        authAlert.style.display = 'block';
    }
});