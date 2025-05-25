// Basic script for interactivity

document.addEventListener('DOMContentLoaded', () => {
    // FAQ Accordion
    const faqItems = document.querySelectorAll('.faq-item');

    faqItems.forEach(item => {
        const question = item.querySelector('.faq-question');
        question.addEventListener('click', () => {
            const isActive = item.classList.contains('active');
            // Close all items first
            faqItems.forEach(otherItem => {
                otherItem.classList.remove('active');
            });
            // If the clicked item wasn't active, open it
            if (!isActive) {
                item.classList.add('active');
            }
        });
    });

    // Navigation Menu Toggle
    const menuButton = document.getElementById('menuButton');
    const navLinks = document.getElementById('navLinks');

    if (menuButton && navLinks) {
        menuButton.addEventListener('click', () => {
            navLinks.classList.toggle('active');
        });
    }
});
