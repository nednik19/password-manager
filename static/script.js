// Get the CSRF token from the hidden input field in the form
const csrfToken = document.querySelector('input[name="csrf_token"]').value;

// Function to fetch passwords from the API
async function fetchPasswords() {
    console.log('Fetching passwords from the API...');
    try {
        const response = await fetch('/api/get_passwords', { credentials: 'same-origin' });
        console.log('API response:', response);
        if (response.ok) {
            const passwords = await response.json();
            console.log('Passwords fetched:', passwords);
            renderPasswords(passwords);
        } else if (response.redirected) {
            console.log('Redirected to:', response.url);
            showPopup('Session expired. Please log in again.');
            window.location.href = response.url;
        } else {
            const errorData = await response.json();
            console.log('Error fetching passwords:', errorData);
            showPopup(errorData.error);
        }
    } catch (error) {
        console.log('Error occurred while fetching passwords:', error);
        showPopup('Error fetching passwords. Please try again later.');
    }
}

// Function to render passwords
function renderPasswords(passwords) {
    const passwordList = document.getElementById('password-list');
    passwordList.innerHTML = '';

    passwords.forEach((item, index) => {
        const listItem = document.createElement('li');

        // Create a span for website and password
        const passwordSpan = document.createElement('span');
        passwordSpan.innerHTML = `
        <strong>${item.website}</strong>: 
        <span class="password" id="password-${index}">${'*'.repeat(item.password.length)}</span>
        <i class="fas fa-eye show-password" title="Show/Hide Password" data-index="${index}" data-password="${item.password}"></i>
        `;
        
        // Create a div for action buttons
        const actionsDiv = document.createElement('div');
        actionsDiv.classList.add('actions');
        actionsDiv.innerHTML = `
        <i class="fas fa-copy copy-password" title="Copy" data-password="${item.password}"></i>
        <i class="fas fa-edit edit-password" title="Edit" data-website="${item.website}"></i>
        <i class="fas fa-trash-alt delete-password" title="Delete" data-website="${item.website}"></i>
        `;
        
        // Append elements to list item
        listItem.appendChild(passwordSpan);
        listItem.appendChild(actionsDiv);
        passwordList.appendChild(listItem);
    });

    addEventListeners();
}

// Function to add event listeners for action buttons
function addEventListeners() {
    document.querySelectorAll('.show-password').forEach(element => {
        element.addEventListener('click', (event) => {
            const index = event.target.getAttribute('data-index');
            const password = event.target.getAttribute('data-password');
            togglePassword(index, password);
        });
    });

    document.querySelectorAll('.copy-password').forEach(element => {
        element.addEventListener('click', (event) => {
            const password = event.target.getAttribute('data-password');
            copyPassword(password);
        });
    });

    document.querySelectorAll('.edit-password').forEach(element => {
        element.addEventListener('click', (event) => {
            const website = event.target.getAttribute('data-website');
            promptEditPassword(website);
        });
    });

    document.querySelectorAll('.delete-password').forEach(element => {
        element.addEventListener('click', (event) => {
            const website = event.target.getAttribute('data-website');
            confirmDelete(website);
        });
    });
}

// Function to add a new password
document.getElementById('add-btn').addEventListener('click', async () => {
    const website = document.getElementById('website').value;
    const password = document.getElementById('password').value;

    if (website && password) {
        try {
            console.log('Adding password:', { website, password });
            const response = await fetch('/add_password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'X-CSRFToken': csrfToken  // Add CSRF token here
                },
                body: new URLSearchParams({
                    'site': website,
                    'password': password
                }),
                credentials: 'same-origin'
            });
            console.log('Add password API response:', response);

            if (response.ok) {
                console.log('Password added successfully.');
                fetchPasswords();
                document.getElementById('website').value = '';
                document.getElementById('password').value = '';

            } else if (response.redirected) {
                console.log('Redirected to:', response.url);
                showPopup('Session expired. Please log in again.');
                window.location.href = response.url;
            } else {
                console.log('Error adding password:', response.statusText);
                showPopup('Error adding password. Please try again later.');
            }
        } catch (error) {
            console.log('Error occurred while adding password:', error);
            showPopup('Error adding password. Please try again later.');
        }
    } else {
        showPopup('Please fill in all fields.');
    }
});

// Function to copy a password
function copyPassword(password) {
    navigator.clipboard.writeText(password);
    showPopup('Password copied to clipboard.');
}

// Function to show custom popup
function showPopup(message, hasCancel = false, isEditing = false, index = null) {
    const popup = document.getElementById('custom-popup');
    const popupMessage = document.getElementById('popup-message');
    const popupInputContainer = document.getElementById('popup-input-container');
    const popupInput = document.getElementById('popup-input');

    popupMessage.textContent = message;
    popupInputContainer.classList.toggle('hidden', !isEditing);
    document.getElementById('popup-cancel').classList.toggle('hidden', !hasCancel);

    if (isEditing && index !== null) {
        popupInput.value = getPasswords()[index].password;
    }

    popup.classList.remove('hidden');

    return new Promise((resolve) => {
        document.getElementById('popup-ok').onclick = () => {
            if (isEditing && index !== null) {
                const newPassword = popupInput.value;
                if (newPassword) {
                    updatePassword(index, newPassword);
                } else {
                    showPopup('Password cannot be empty.');
                    return;
                }
            }
            popup.classList.add('hidden');
            resolve(true);
        };
        if (hasCancel) {
            document.getElementById('popup-cancel').onclick = () => {
                popup.classList.add('hidden');
                resolve(false);
            };
        }
    });
}

// Function to confirm deletion with custom popup
async function confirmDelete(site) {
    const confirmed = await showPopup('Are you sure you want to delete this password?', true);
    if (confirmed) {
        try {
            console.log('Deleting password for site:', site);
            const response = await fetch('/api/delete_password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken,  // Add CSRF token here
                },
                body: JSON.stringify({
                    'site': site
                }),
                credentials: 'same-origin'
            });
            console.log('Delete password API response:', response);

            if (response.ok) {
                console.log('Password deleted successfully.');
                fetchPasswords();
            } else {
                const errorData = await response.json();
                console.log('Error deleting password:', errorData);
                showPopup(errorData.error);
            }
        } catch (error) {
            console.log('Error occurred while deleting password:', error);
            showPopup('Error deleting password. Please try again later.');
        }
    }
}

// Function to prompt for editing a password
async function promptEditPassword(site) {
    const confirmed = await showPopup('Enter new password:', false, true);
    if (confirmed) {
        const newPassword = document.getElementById('popup-input').value;
        if (newPassword) {
            try {
                console.log('Updating password for site:', site);
                const response = await fetch('/api/update_password', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': csrfToken,  // Add CSRF token here
                    },
                    body: JSON.stringify({
                        'site': site,
                        'new_password': newPassword
                    }),
                    credentials: 'same-origin'
                });
                console.log('Update password API response:', response);

                if (response.ok) {
                    console.log('Password updated successfully.');
                    fetchPasswords();
                } else {
                    const errorData = await response.json();
                    console.log('Error updating password:', errorData);
                    showPopup(errorData.error);
                }
            } catch (error) {
                console.log('Error occurred while updating password:', error);
                showPopup('Error updating password. Please try again later.');
            }
        } else {
            showPopup('Password cannot be empty.');
        }
    }
}

// Function to toggle the visibility of the password
function togglePassword(index, password) {
    const passwordSpan = document.getElementById(`password-${index}`);
    if (passwordSpan.textContent === '*'.repeat(password.length)) {
        passwordSpan.textContent = password;
    } else {
        passwordSpan.textContent = '*'.repeat(password.length);
    }
}

// Initial fetch of passwords
fetchPasswords();