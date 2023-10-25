//settings button
document.getElementById('settings-button').addEventListener('click', function() {
    var console = document.getElementById('settings-console');
    if (console.classList.contains('hidden')) {
        console.classList.remove('hidden');
    } else {
        console.classList.add('hidden');
    }
});
//logout button functionality 
document.addEventListener('DOMContentLoaded', (event) => {
    // This ensures that the DOM is fully loaded before attaching an event
    var logoutButton = document.getElementById('logout-button');
    if(logoutButton) { // Check if logoutButton exists to avoid null reference errors
        logoutButton.addEventListener('click', function() {
            document.getElementById('logout-form').submit();
        });
    }
});
//console .shrinking animation
