document.addEventListener('submit', (event) => {
  const form = event.target;
  const passwordInputs = form.querySelectorAll('input[type="password"]');
  const usernameInputs = form.querySelectorAll('input[type="email"], input[type="text"][autocomplete="username"]');

  if (passwordInputs.length > 0 && usernameInputs.length > 0) {
    const password = passwordInputs[0].value;
    const username = usernameInputs[0].value;
    const website = window.location.hostname;

    if (password && username) {
      chrome.runtime.sendMessage({
        action: "savePassword",
        website: website,
        username: username,
        password: password
      });
    }
  }
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "autofill") {
    chrome.storage.local.get('loggedIn', (data) => {
        if(data.loggedIn) {
            const passwordInputs = document.querySelectorAll('input[type="password"]');
            const usernameInputs = document.querySelectorAll('input[type="email"], input[type="text"][autocomplete="username"]');

            if (passwordInputs.length > 0 && usernameInputs.length > 0) {
              usernameInputs[0].value = request.username;
              passwordInputs[0].value = request.password;
            }
        }
    });
  }
});
