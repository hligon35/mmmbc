// Basic script for interactivity

document.addEventListener('DOMContentLoaded', () => {
    // Remove dev/admin and login shortcuts from the public nav (local request).
    document.querySelectorAll('.devicon-btn').forEach((el) => el.remove());
    document.querySelectorAll('.nav-links').forEach((nav) => {
        nav.querySelectorAll('a').forEach((a) => {
            const text = String(a.textContent || '').trim().toLowerCase();
            const href = String(a.getAttribute('href') || '').trim().toLowerCase();
            const isAdminHref = href === '../admin/' || href === '/admin/' || href.endsWith('/admin/');
            if (text === 'login' && isAdminHref) a.remove();
        });
    });

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

    // Contact page: ensure the contact form is visible when present
    const contactForm = document.getElementById('contactInfoForm');
    if (contactForm) {
        contactForm.classList.remove('hidden');
    }

    // Site settings: update social/contact links from exported site-settings.json
    const normalizePhoneDigits = (value) => String(value || '').replace(/\D/g, '');
    const buildMapsUrl = (address) => {
        const q = encodeURIComponent(String(address || '').trim());
        return q ? `https://www.google.com/maps/search/?api=1&query=${q}` : '';
    };

    const tryFetchJson = async (urls) => {
        for (const url of urls) {
            try {
                const res = await fetch(url, { cache: 'no-store' });
                if (!res.ok) continue;
                return await res.json();
            } catch {
                // try next
            }
        }
        return null;
    };

    const applySiteSettings = (settings) => {
        if (!settings || typeof settings !== 'object') return;

        // Footer "Connect With Us" section
        const connect = document.getElementById('connect-us');
        if (connect) {
            const anchors = Array.from(connect.querySelectorAll('a'));
            for (const a of anchors) {
                const href = String(a.getAttribute('href') || '');
                const span = a.querySelector('.link-text');

                if (href.startsWith('tel:') && settings.phone) {
                    const digits = normalizePhoneDigits(settings.phone);
                    if (digits) a.setAttribute('href', `tel:${digits}`);
                    if (span) span.textContent = String(settings.phone);
                }

                if (href.startsWith('mailto:') && settings.email) {
                    a.setAttribute('href', `mailto:${String(settings.email).trim()}`);
                    // Keep "Email Us" label unless it's showing an actual address.
                    if (span && span.textContent.includes('@')) span.textContent = String(settings.email).trim();
                }

                if (href.includes('facebook.com') && settings.facebook) {
                    a.setAttribute('href', String(settings.facebook).trim());
                }

                if (href.includes('youtube.com') && settings.youtube) {
                    a.setAttribute('href', String(settings.youtube).trim());
                }

                if ((href.includes('google.com/maps') || href.includes('maps/search')) && settings.address) {
                    const url = buildMapsUrl(settings.address);
                    if (url) a.setAttribute('href', url);
                    if (span) span.textContent = String(settings.address);
                }
            }
        }

        // Contact page cards + forms (only touch generic tel/mailto)
        if (settings.phone) {
            const digits = normalizePhoneDigits(settings.phone);
            if (digits) {
                document.querySelectorAll('a[href^="tel:"]').forEach((a) => {
                    // Avoid overwriting other non-footer numbers; only update the church office default.
                    const href = String(a.getAttribute('href') || '');
                    if (href.includes('2704433714')) {
                        a.setAttribute('href', `tel:${digits}`);
                        if (a.textContent && a.textContent.includes('270')) a.textContent = String(settings.phone);
                    }
                });
            }
        }

        if (settings.email) {
            const email = String(settings.email).trim();
            document.querySelectorAll('a[href^="mailto:"]').forEach((a) => {
                const href = String(a.getAttribute('href') || '');
                if (href.includes('mtmoriahmbc1201@gmail.com')) {
                    a.setAttribute('href', `mailto:${email}`);
                    if (a.textContent && a.textContent.includes('@')) a.textContent = email;
                }
            });

            document.querySelectorAll('form[action^="mailto:"]').forEach((f) => {
                const action = String(f.getAttribute('action') || '');
                if (action.includes('mtmoriahmbc1201@gmail.com')) {
                    f.setAttribute('action', `mailto:${email}`);
                }
            });
        }
    };

    (async () => {
        const settings = await tryFetchJson(['site-settings.json', '../site-settings.json', '/site-settings.json']);
        if (settings) applySiteSettings(settings);
    })();
});
