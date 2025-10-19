document.addEventListener('DOMContentLoaded', async () => {
    const navbarPlaceholder = document.getElementById('navbar-placeholder');

    if (navbarPlaceholder) {
        try {
            // 1. Fetch and inject the navbar HTML
            const response = await fetch('navbar.html');
            if (!response.ok) throw new Error('navbar.html not found');
            const navbarHtml = await response.text();
            navbarPlaceholder.innerHTML = navbarHtml;

            // 2. Get references to ALL dynamic elements AFTER they are loaded
            // Desktop elements
            const myAccountLink = document.getElementById('nav-my-account');
            const loginRegisterDiv = document.getElementById('nav-login-register');
            const logoutButton = document.getElementById('nav-logout');

            // Mobile elements
            const myAccountLinkMobile = document.getElementById('nav-my-account-mobile');
            const loginRegisterDivMobile = document.getElementById('nav-login-register-mobile');
            const logoutButtonMobile = document.getElementById('nav-logout-mobile');
            
            // Hamburger menu elements
            const hamburgerButton = document.getElementById('hamburger-button');
            const mobileMenu = document.getElementById('mobile-menu');

            // 3. Add Hamburger Menu functionality
            if (hamburgerButton && mobileMenu) {
                hamburgerButton.addEventListener('click', () => {
                    mobileMenu.classList.toggle('hidden');
                });
            }

            // 4. Check for user token
            const token = localStorage.getItem('token') || localStorage.getItem('admin_token');

            if (token) {
                // User is LOGGED IN
                myAccountLink.classList.remove('hidden');
                logoutButton.classList.remove('hidden');
                loginRegisterDiv.classList.add('hidden');
                
                myAccountLinkMobile.classList.remove('hidden');
                logoutButtonMobile.classList.remove('hidden');
                loginRegisterDivMobile.classList.add('hidden');

                // Add event listeners for both logout buttons
                const handleLogout = () => {
                    localStorage.removeItem('token');
                    localStorage.removeItem('admin_token');
                    window.location.href = 'index.html';
                };
                logoutButton.addEventListener('click', handleLogout);
                logoutButtonMobile.addEventListener('click', handleLogout);

            } else {
                // User is LOGGED OUT
                myAccountLink.classList.add('hidden');
                logoutButton.classList.add('hidden');
                loginRegisterDiv.classList.remove('hidden');
                
                myAccountLinkMobile.classList.add('hidden');
                logoutButtonMobile.classList.add('hidden');
                loginRegisterDivMobile.classList.remove('hidden');
            }

        } catch (error) {
            console.error("Error loading navbar:", error);
        }
    }
});