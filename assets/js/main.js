document.addEventListener('DOMContentLoaded', function() {
    const domainInput = document.getElementById('domain');
    const resultsContainer = document.querySelector('.results-container');
    const loadingAnimation = document.querySelector('.loading-animation');
    const form = document.querySelector('form');

    // Clear results when typing in domain input
    domainInput.addEventListener('input', function() {
        if (resultsContainer) {
            resultsContainer.style.display = 'none';
        }
    });

    // Show loading animation when form is submitted
    form.addEventListener('submit', function() {
        if (loadingAnimation) {
            loadingAnimation.style.display = 'flex';
        }
        if (resultsContainer) {
            resultsContainer.style.display = 'none';
        }
    });
});
