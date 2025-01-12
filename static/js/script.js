document.addEventListener('DOMContentLoaded', () => {
    const toggleButton = document.querySelector('.toggle-menu');
    const navLinks = document.querySelector('.nav-links');

    toggleButton.addEventListener('click', () => {
        navLinks.classList.toggle('active');
    });
});

/**------------------------- */
function toggleModal() {
    const modal = document.getElementById('addPasswordModal');
    if (modal.style.display === 'flex') {
        modal.style.display = 'none';
    } else {
        modal.style.display = 'flex';
    }
}

/*-----------------Anayze password------------------*/
function analyzePassword() {
    const password = document.getElementById('password').value;
    fetch('/analyze_password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
    })
        .then((response) => response.json())
        .then((data) => {
            document.getElementById('password-strength').textContent = data.strength;
            document.getElementById('password-score').textContent = data.score;
        })
        .catch((error) => console.error('Error analyzing password:', error));
}

/*-------------------------------- Generate pass---------------------------*/
function generatePassword() {
    const length = document.getElementById('length').value || 12;
    
    fetch(`/generate_password?length=${length}`)
        .then((response) => {
            if (!response.ok) {
                throw new Error("Failed to generate password");
            }
            return response.json();
        })
        .then((data) => {
            if (data.password) {
                const passwordField = document.getElementById('password');
                const generatedPasswordText = document.getElementById('generated-password');
                // Set the password field and display the generated password
                passwordField.value = data.password;
                generatedPasswordText.textContent = `Generated: ${data.password}`;
            } else {
                alert("Error generating password.");
            }
        })
        .catch((error) => {
            console.error("Error:", error);
            alert("An error occurred while generating the password.");
        });
}

/*-----------------------------------------row edition-------------- */
function editEntry(id) {
    // Hide the display row and show the edit form row
    document.getElementById(`password-row-${id}`).style.display = "none";
    document.getElementById(`edit-row-${id}`).style.display = "table-row";
}

function cancelEdit(id) {
    // Hide the edit form row and show the display row
    document.getElementById(`password-row-${id}`).style.display = "table-row";
    document.getElementById(`edit-row-${id}`).style.display = "none";
}

function updateEntry(event, id) {
    event.preventDefault();
    const form = event.target;
    const formData = new FormData(form);

    fetch(`/update_password/${id}`, {
        method: "POST",
        body: JSON.stringify({
            account: formData.get("account"),
            username: formData.get("username"),
            password: formData.get("password"),
        }),
        headers: {
            "Content-Type": "application/json",
        },
    })
        .then((response) => {
            if (!response.ok) {
                throw new Error("Failed to update entry.");
            }
            return response.json();
        })
        .then((data) => {
            if (data.success) {
                // Update the display row with new values
                document.getElementById(`password-row-${id}`).innerHTML = `
                    <td>${data.updated.account}</td>
                    <td>${data.updated.username}</td>
                    <td>${data.updated.hash}</td>
                    <td>
                        <span class="ciphertext" id="ciphertext-${id}">${data.updated.password}</span>
                    </td>
                    <td>
                        <button class="action-btn show-btn" onclick="showPassword(${id})">
                            <i class="fas fa-eye"></i>
                        </button>
                        <button class="action-btn edit-btn" onclick="editEntry(${id})">
                            <i class="fas fa-edit"></i>
                        </button>
                        <button class="action-btn delete-btn" onclick="deletePassword(${id})">
                            <i class="fas fa-trash"></i>
                        </button>
                    </td>
                `;
                cancelEdit(id);
            } else {
                alert("Error: Unable to update entry.");
            }
        })
        .catch((error) => {
            console.error("Error:", error);
            alert("An error occurred while updating the entry.");
        });
}

/*-------------------------------------Password interactions --------------- */
function showPassword(id) {
    const ciphertextElement = document.getElementById(`ciphertext-${id}`);
    if (ciphertextElement) {
        if (ciphertextElement.dataset.plaintext) {
            // Toggle back to ciphertext
            ciphertextElement.textContent = ciphertextElement.dataset.plaintext;
            delete ciphertextElement.dataset.plaintext;
        } else {
            // Fetch plaintext password from the server
            fetch(`/decrypt_password/${id}`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
            })
                .then((response) => {
                    if (!response.ok) {
                        throw new Error("Failed to decrypt password");
                    }
                    return response.json();
                })
                .then((data) => {
                    if (data.plaintext) {
                        // Store the ciphertext for toggling back
                        ciphertextElement.dataset.plaintext = ciphertextElement.textContent;
                        // Display the plaintext password
                        ciphertextElement.textContent = data.plaintext;
                    } else {
                        alert("Error: Could not decrypt password.");
                    }
                })
                .catch((error) => {
                    console.error("Error:", error);
                    alert("An error occurred while decrypting the password.");
                });
        }
    }
}


function deletePassword(id) {
    if (confirm("Are you sure you want to delete this password?")) {
        fetch(`/delete_password/${id}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
        })
            .then((response) => response.json())
            .then((data) => {
                if (data.success) {
                    const row = document.getElementById(`password-row-${id}`);
                    if (row) row.remove();
                } else {
                    alert("Error deleting password.");
                }
            });
    }
}
