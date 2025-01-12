document.addEventListener('DOMContentLoaded', () => {
    const acceptCookiesButton = document.getElementById('accept-cookies');
    if (acceptCookiesButton) {
        acceptCookiesButton.addEventListener('click', () => {
            fetch('/accept_cookies', { method: 'GET' })
                .then(() => {
                    const banner = document.getElementById('cookies-banner');
                    if (banner) {
                        banner.style.display = 'none';
                    }
                })
                .catch((error) => console.error('Error accepting cookies:', error));
        });
    }
});
