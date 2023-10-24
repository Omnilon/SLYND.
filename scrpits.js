document.getElementById('settings-button').addEventListener('click', function() {
    var console = document.getElementById('settings-console');
    if (console.classList.contains('hidden')) {
        console.classList.remove('hidden');
    } else {
        console.classList.add('hidden');
    }
});
