chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "savePassword") {
    chrome.storage.local.get('loggedIn', (data) => {
      if (data.loggedIn) {
        chrome.windows.create({
          url: "save_password_prompt.html",
          type: "popup",
          width: 400,
          height: 300
        }, (window) => {
          chrome.storage.local.set({
            'pendingPassword': {
              website: request.website,
              username: request.username,
              password: request.password
            }
          });
        });
      }
    });
  } else if (request.action === "savePasswordFromPrompt") {
    chrome.storage.local.get('loggedIn', (data) => {
        if (data.loggedIn) {
            fetch('http://127.0.0.1:5000/passwords', {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    website: request.website,
                    username: request.username,
                    password: request.password
                }),
              })
              .then(response => response.json())
              .then(data => {
                if (data.message) {
                    sendResponse({success: true});
                } else {
                    sendResponse({success: false, error: data.error});
                }
              })
              .catch((error) => {
                console.error('Error:', error);
                sendResponse({success: false, error: 'Could not connect to the server.'});
              });
        } else {
            sendResponse({success: false, error: "User not logged in."})
        }
    });
    return true; // Indicates that the response is sent asynchronously
  }
});
