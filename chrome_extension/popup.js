document.addEventListener('DOMContentLoaded', function() {
  const loginView = document.getElementById('login-view');
  const passwordListView = document.getElementById('password-list-view');
  const addPasswordView = document.getElementById('add-password-view');

  const masterPasswordInput = document.getElementById('master-password');
  const loginButton = document.getElementById('login-button');

  const passwordList = document.getElementById('password-list');
  const addPasswordButton = document.getElementById('add-password-button');

  const websiteInput = document.getElementById('website');
  const usernameInput = document.getElementById('username');
  const passwordInput = document.getElementById('password');
  const savePasswordButton = document.getElementById('save-password-button');
  const cancelAddPasswordButton = document.getElementById('cancel-add-password-button');

  loginButton.addEventListener('click', () => {
    const masterPassword = masterPasswordInput.value;
    fetch('http://127.0.0.1:5000/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ master_password: masterPassword }),
    })
    .then(response => response.json())
    .then(data => {
      if (data.message) {
        loginView.style.display = 'none';
        passwordListView.style.display = 'block';
        loadPasswords();
      } else {
        alert(data.error);
      }
    })
    .catch((error) => {
      console.error('Error:', error);
      alert('Could not connect to the server. Make sure the desktop app is running.');
    });
  });

  addPasswordButton.addEventListener('click', () => {
    passwordListView.style.display = 'none';
    addPasswordView.style.display = 'block';
  });

  cancelAddPasswordButton.addEventListener('click', () => {
    addPasswordView.style.display = 'none';
    passwordListView.style.display = 'block';
  });

  savePasswordButton.addEventListener('click', () => {
    const website = websiteInput.value;
    const username = usernameInput.value;
    const password = passwordInput.value;

    fetch('http://127.0.0.1:5000/passwords', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ website, username, password }),
    })
    .then(response => response.json())
    .then(data => {
      if (data.message) {
        addPasswordView.style.display = 'none';
        passwordListView.style.display = 'block';
        loadPasswords();
      } else {
        alert(data.error);
      }
    })
    .catch((error) => {
      console.error('Error:', error);
    });
  });

  function loadPasswords() {
    fetch('http://127.0.0.1:5000/passwords')
    .then(response => response.json())
    .then(data => {
      passwordList.innerHTML = '';
      data.forEach(item => {
        const li = document.createElement('li');
        li.textContent = `${item.website} - ${item.username}`;
        const copyButton = document.createElement('button');
        copyButton.textContent = 'Copy';
        copyButton.onclick = () => {
            navigator.clipboard.writeText(item.password);
            alert('Password copied to clipboard');
        };
        li.appendChild(copyButton);
        passwordList.appendChild(li);
      });
    })
    .catch((error) => {
      console.error('Error:', error);
    });
  }
});
