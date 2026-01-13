// Basic script for interactivity

document.addEventListener('DOMContentLoaded', () => {
    // FAQ Accordion
    const faqItems = document.querySelectorAll('.faq-item');

    faqItems.forEach(item => {
        const question = item.querySelector('.faq-question');
        const answer = item.querySelector('.faq-answer');

        if (question) {
            // Make headings keyboard-focusable and announce expanded state
            if (!question.hasAttribute('tabindex')) question.setAttribute('tabindex', '0');
            question.setAttribute('role', 'button');

            if (answer) {
                if (!answer.id) {
                    answer.id = `faq-answer-${Math.random().toString(36).slice(2, 9)}`;
                }
                question.setAttribute('aria-controls', answer.id);
            }

            question.setAttribute('aria-expanded', item.classList.contains('active') ? 'true' : 'false');

            question.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    question.click();
                }
            });
        }

        question.addEventListener('click', () => {
            const isActive = item.classList.contains('active');
            // Close all items first
            faqItems.forEach(otherItem => {
                otherItem.classList.remove('active');
                const otherQuestion = otherItem.querySelector('.faq-question');
                if (otherQuestion) otherQuestion.setAttribute('aria-expanded', 'false');
            });
            // If the clicked item wasn't active, open it
            if (!isActive) {
                item.classList.add('active');
                if (question) question.setAttribute('aria-expanded', 'true');
            }
        });
    });

    // Navigation Menu Toggle
    const menuButton = document.getElementById('menuButton');
    const navLinks = document.getElementById('navLinks');

    if (menuButton && navLinks) {
        const setExpanded = (expanded) => {
            menuButton.setAttribute('aria-expanded', expanded ? 'true' : 'false');
        };

        // Ensure sensible defaults even if markup is missing attributes
        if (!menuButton.hasAttribute('aria-controls')) {
            menuButton.setAttribute('aria-controls', 'navLinks');
        }
        setExpanded(navLinks.classList.contains('active'));

        menuButton.addEventListener('click', () => {
            navLinks.classList.toggle('active');
            setExpanded(navLinks.classList.contains('active'));
        });

        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && navLinks.classList.contains('active')) {
                navLinks.classList.remove('active');
                setExpanded(false);
                menuButton.focus();
            }
        });
    }

    // Contact page: toggle between Prayer Request and Contact Information forms
    const prayerForm = document.getElementById('prayerRequestForm');
    const contactForm = document.getElementById('contactInfoForm');
    const prayerBtn = document.getElementById('showPrayerFormBtn');
    const contactBtn = document.getElementById('showContactFormBtn');

    if (prayerForm && contactForm && prayerBtn && contactBtn) {
        const showForm = (formIdToShow) => {
            const showPrayer = formIdToShow === 'prayerRequestForm';
            prayerForm.classList.toggle('hidden', !showPrayer);
            contactForm.classList.toggle('hidden', showPrayer);
            prayerBtn.classList.toggle('active', showPrayer);
            contactBtn.classList.toggle('active', !showPrayer);
        };

        prayerBtn.addEventListener('click', () => showForm('prayerRequestForm'));
        contactBtn.addEventListener('click', () => showForm('contactInfoForm'));
        showForm('prayerRequestForm');
    }
});
