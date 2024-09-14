document.addEventListener('DOMContentLoaded', function () {
    const options = document.querySelectorAll('.option');
    const continueButton = document.querySelector('.continue-button');
    let selectedOption = null;

    // Add click event to each option
    options.forEach(option => {
        option.addEventListener('click', function () {
            // Remove 'selected' class from all options
            options.forEach(opt => opt.classList.remove('selected'));
            
            // Add 'selected' class to the clicked option
            this.classList.add('selected');

            // Enable continue button
            selectedOption = this.getAttribute('data-value');
            continueButton.classList.add('active');
            continueButton.disabled = false;
        });
    });

    // Redirect to the signup page on continue button click
    continueButton.addEventListener('click', function () {
        if (selectedOption) {
            // Assuming you have different signup routes for hospitals and research centers
            if (selectedOption === 'hospitals') {
                window.location.href = '/signup';  // Replace with actual signup route
            } else if (selectedOption === 'research') {
                window.location.href = '/signup';   // Replace with actual signup route
            }
        }
    });
});
