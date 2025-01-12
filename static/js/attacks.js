document.addEventListener('DOMContentLoaded', () => {
    const attackTypeSelect = document.getElementById('attack_type');
    const bruteForceOptions = document.getElementById('brute-force-options');
    const dictionaryOptions = document.getElementById('dictionary-options');
    const form = document.getElementById('attack-form');
    const resultsDiv = document.getElementById('results');

    attackTypeSelect.addEventListener('change', () => {
        if (attackTypeSelect.value === 'brute_force') {
            bruteForceOptions.style.display = 'block';
            dictionaryOptions.style.display = 'none';
        } else if (attackTypeSelect.value === 'dictionary') {
            bruteForceOptions.style.display = 'none';
            dictionaryOptions.style.display = 'block';
        } else {
            bruteForceOptions.style.display = 'none';
            dictionaryOptions.style.display = 'none';
        }
    });

    form.addEventListener('submit', (event) => {
        event.preventDefault();
        const formData = new FormData(form);

        fetch('/attacks', {
            method: 'POST',
            body: formData,
        })
            .then(response => {
                if (!response.ok) {
                    return response.json().then(errorData => {
                        throw new Error(errorData.error || "An unknown error occurred.");
                    });
                }
                return response.json();
            })
            .then(data => {
                resultsDiv.style.display = 'block';
                document.getElementById('result-type').textContent = data.type;
                document.getElementById('result-plaintext').textContent = data.plaintext || 'Not found';
                document.getElementById('result-attempts').textContent = data.attempts;
                document.getElementById('result-duration').textContent = data.duration.toFixed(2);
            })
            .catch(error => {
                alert(`Error: ${error.message}`);
            });
    });
});
