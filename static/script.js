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
        <i class="fas fa-eye show-password" onclick="togglePassword(${index})" title="Show/Hide Password"></i> 
        `;
        
        // Create a div for action buttons
        const actionsDiv = document.createElement('div');
        actionsDiv.classList.add('actions');
        actionsDiv.innerHTML = `
        <i class="fas fa-copy" onclick="copyPassword(${index}, '${item.password}')" title="Copy"></i>
        <i class="fas fa-edit" onclick="promptEditPassword(${index})" title="Edit"></i>
        <i class="fas fa-trash-alt" onclick="confirmDelete(${index})" title="Delete"></i>
        `;
        
        // Append elements to list item
        listItem.appendChild(passwordSpan);
        listItem.appendChild(actionsDiv);
        passwordList.appendChild(listItem);
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
function copyPassword(index, password) {
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
                    // Update password logic to be implemented
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
async function confirmDelete(index) {
    const confirmed = await showPopup('Are you sure you want to delete this password?', true);
    if (confirmed) {
        // Delete password logic to be implemented
    }
}

// Function to prompt for editing a password
async function promptEditPassword(index) {
    await showPopup('Enter new password:', false, true, index);
}

// Function to toggle the visibility of the password
function togglePassword(index) {
    const passwordSpan = document.getElementById(`password-${index}`);
    if (passwordSpan.textContent === '*'.repeat(passwordSpan.textContent.length)) {
        passwordSpan.textContent = passwordSpan.dataset.password;
    } else {
        passwordSpan.textContent = '*'.repeat(passwordSpan.dataset.password.length);
    }
}

// Initial fetch of passwords
fetchPasswords();