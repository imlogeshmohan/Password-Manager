document.addEventListener('DOMContentLoaded', function() {
  const websiteInput = document.getElementById('website');
  const usernameInput = document.getElementById('username');
  const passwordInput = document.getElementById('password');
  const savePasswordButton = document.getElementById('save-password-button');
  const cancelAddPasswordButton = document.getElementById('cancel-add-password-button');

  chrome.storage.local.get('pendingPassword', (data) => {
    if (data.pendingPassword) {
      websiteInput.value = data.pendingPassword.website;
      usernameInput.value = data.pendingPassword.username;
      passwordInput.value = data.pendingPassword.password;
    }
  });

  savePasswordButton.addEventListener('click', () => {
    const website = websiteInput.value;
    const username = usernameInput.value;
    const password = passwordInput.value;

    chrome.runtime.sendMessage({
        action: "savePasswordFromPrompt",
        website: website,
        username: username,
        password: password
    }, function(response) {
        if (response.success) {
            chrome.storage.local.remove('pendingPassword');
            window.close();
        } else {
            alert(response.error);
        }
    });
  });

  cancelAddPasswordButton.addEventListener('click', () => {
    chrome.storage.local.remove('pendingPassword');
    window.close();
  });
});
