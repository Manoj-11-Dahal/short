// Wait for DOM to fully load
document.addEventListener('DOMContentLoaded', function() {
    // Initialize animations
    initAnimations();
    
    // Initialize particles background
    initParticles();
    
    // Initialize skill bars animation
    initSkillBars();
    
    // Mobile menu toggle
    initMobileMenu();
    
    // Contact form handling
    initContactForm();
    
    // Project modal functionality
    initProjectModal();
    
    // Initialize custom cursor
    initCustomCursor();
});

// Initialize custom cursor functionality
function initCustomCursor() {
    const cursor = document.querySelector('.cursor');
    const cursorDot = document.querySelector('.cursor-dot');
    
    // Check if cursor elements exist and if device is not mobile
    if (!cursor || !cursorDot || window.innerWidth <= 768) {
        return;
    }
    
    const links = document.querySelectorAll('a, button, .btn, .project-card, .social-link');
    
    // Track mouse movement with smooth animation
    let mouseX = 0;
    let mouseY = 0;
    let cursorX = 0;
    let cursorY = 0;
    
    document.addEventListener('mousemove', (e) => {
        // Update mouse position
        mouseX = e.clientX;
        mouseY = e.clientY;
        
        // Cursor dot follows immediately
        cursorDot.style.left = mouseX + 'px';
        cursorDot.style.top = mouseY + 'px';
    });
    
    // Smooth animation for main cursor
    function animateCursor() {
        // Calculate smooth movement with easing
        const easeFactor = 0.15;
        cursorX += (mouseX - cursorX) * easeFactor;
        cursorY += (mouseY - cursorY) * easeFactor;
        
        // Apply position with smooth transition
        cursor.style.left = cursorX + 'px';
        cursor.style.top = cursorY + 'px';
        
        // Continue animation loop
        requestAnimationFrame(animateCursor);
    }
    
    // Start the animation loop
    animateCursor();
    
    // Add hover effect when mouse is over interactive elements
    links.forEach(link => {
        link.addEventListener('mouseenter', () => {
            cursor.classList.add('hover');
            cursorDot.classList.add('cursor-pulse');
        });
        
        link.addEventListener('mouseleave', () => {
            cursor.classList.remove('hover');
            cursorDot.classList.remove('cursor-pulse');
        });
    });
    
    // Add click animation effect
    document.addEventListener('mousedown', () => {
        cursor.style.transform = 'translate(-50%, -50%) scale(0.8)';
        cursorDot.style.transform = 'translate(-50%, -50%) scale(0.5)';
        cursor.classList.add('click-animation');
    });
    
    document.addEventListener('mouseup', () => {
        cursor.style.transform = 'translate(-50%, -50%) scale(1)';
        cursorDot.style.transform = 'translate(-50%, -50%) scale(1)';
        setTimeout(() => {
            cursor.classList.remove('click-animation');
        }, 300);
    });
    
    // Hide cursor when mouse leaves the window
    document.addEventListener('mouseout', (e) => {
        if (e.relatedTarget === null) {
            cursor.style.display = 'none';
            cursorDot.style.display = 'none';
        }
    });
    
    document.addEventListener('mouseover', () => {
        cursor.style.display = 'block';
        cursorDot.style.display = 'block';
    });
    
    // Add special effects for specific elements
    const glowElements = document.querySelectorAll('.glow-effect');
    glowElements.forEach(element => {
        element.addEventListener('mouseenter', () => {
            cursorDot.style.opacity = '0.5';
        });
        
        element.addEventListener('mouseleave', () => {
            cursorDot.style.opacity = '1';
        });
    });
}

// Initialize scroll animations
function initAnimations() {
    const fadeElements = document.querySelectorAll('.fade-in');
    
    // Initial check for elements in viewport on page load
    checkFadeElements();
    
    // Check elements on scroll
    window.addEventListener('scroll', checkFadeElements);
    
    function checkFadeElements() {
        fadeElements.forEach(element => {
            const elementTop = element.getBoundingClientRect().top;
            const elementVisible = 150;
            
            if (elementTop < window.innerHeight - elementVisible) {
                element.classList.add('appear');
            }
        });
    }
}

// Initialize particles.js for background effect
function initParticles() {
    if (typeof particlesJS !== 'undefined') {
        particlesJS('particles-js', {
            particles: {
                number: {
                    value: 80,
                    density: {
                        enable: true,
                        value_area: 800
                    }
                },
                color: {
                    value: '#ffffff'
                },
                shape: {
                    type: 'circle',
                    stroke: {
                        width: 0,
                        color: '#000000'
                    },
                    polygon: {
                        nb_sides: 5
                    }
                },
                opacity: {
                    value: 0.5,
                    random: false,
                    anim: {
                        enable: false,
                        speed: 1,
                        opacity_min: 0.1,
                        sync: false
                    }
                },
                size: {
                    value: 3,
                    random: true,
                    anim: {
                        enable: false,
                        speed: 40,
                        size_min: 0.1,
                        sync: false
                    }
                },
                line_linked: {
                    enable: true,
                    distance: 150,
                    color: '#ffffff',
                    opacity: 0.4,
                    width: 1
                },
                move: {
                    enable: true,
                    speed: 2,
                    direction: 'none',
                    random: false,
                    straight: false,
                    out_mode: 'out',
                    bounce: false,
                    attract: {
                        enable: false,
                        rotateX: 600,
                        rotateY: 1200
                    }
                }
            },
            interactivity: {
                detect_on: 'canvas',
                events: {
                    onhover: {
                        enable: true,
                        mode: 'grab'
                    },
                    onclick: {
                        enable: true,
                        mode: 'push'
                    },
                    resize: true
                },
                modes: {
                    grab: {
                        distance: 140,
                        line_linked: {
                            opacity: 1
                        }
                    },
                    push: {
                        particles_nb: 4
                    }
                }
            },
            retina_detect: true
        });
    }
}

// Initialize skill bars animation
function initSkillBars() {
    const skillLevels = document.querySelectorAll('.skill-level');
    
    // Function to animate skill bars when they come into view
    function animateSkillBars() {
        skillLevels.forEach(skill => {
            const skillTop = skill.getBoundingClientRect().top;
            const skillVisible = 150;
            
            if (skillTop < window.innerHeight - skillVisible) {
                const level = skill.getAttribute('data-level');
                skill.style.width = level;
            }
        });
    }
    
    // Initial check on page load
    animateSkillBars();
    
    // Check on scroll
    window.addEventListener('scroll', animateSkillBars);
}

// Initialize mobile menu functionality
function initMobileMenu() {
    const hamburger = document.querySelector('.hamburger');
    const navLinks = document.querySelector('.nav-links');
    const navLinksItems = document.querySelectorAll('.nav-links li a');
    
    // Toggle mobile menu
    hamburger.addEventListener('click', () => {
        hamburger.classList.toggle('active');
        navLinks.classList.toggle('active');
    });
    
    // Close mobile menu when a link is clicked
    navLinksItems.forEach(item => {
        item.addEventListener('click', () => {
            hamburger.classList.remove('active');
            navLinks.classList.remove('active');
        });
    });
}

// Initialize contact form handling
function initContactForm() {
    const contactForm = document.getElementById('contactForm');
    const formStatus = document.getElementById('formStatus');
    
    if (contactForm) {
        contactForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Get form data
            const formData = new FormData(contactForm);
            
            // Client-side validation
            const name = formData.get('name');
            const email = formData.get('email');
            const message = formData.get('message');
            
            if (!name || !email || !message) {
                showFormStatus('Please fill in all fields', 'error');
                return;
            }
            
            if (!validateEmail(email)) {
                showFormStatus('Please enter a valid email address', 'error');
                return;
            }
            
            // Send form data to server using fetch API
            fetch('php/contact.php', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showFormStatus('Message sent successfully!', 'success');
                    contactForm.reset();
                } else {
                    showFormStatus(data.message || 'An error occurred. Please try again.', 'error');
                }
            })
            .catch(error => {
                showFormStatus('An error occurred. Please try again.', 'error');
                console.error('Error:', error);
            });
        });
    }
    
    // Helper function to validate email format
    function validateEmail(email) {
        const re = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
        return re.test(String(email).toLowerCase());
    }
    
    // Helper function to show form status messages
    function showFormStatus(message, type) {
        formStatus.textContent = message;
        formStatus.className = type;
        
        // Hide status message after 5 seconds
        setTimeout(() => {
            formStatus.style.display = 'none';
            formStatus.className = '';
        }, 5000);
    }
}

// Initialize project modal functionality
function initProjectModal() {
    const projectCards = document.querySelectorAll('.project-card');
    const modal = document.getElementById('projectModal');
    const modalContent = document.getElementById('modalContent');
    const closeModal = document.querySelector('.close-modal');
    
    // Open modal when project card is clicked
    projectCards.forEach(card => {
        card.addEventListener('click', () => {
            // Clone project info for modal
            const projectInfo = card.querySelector('.project-info').cloneNode(true);
            const projectImg = card.querySelector('.project-img img').cloneNode(true);
            
            // Create modal content
            modalContent.innerHTML = '';
            modalContent.appendChild(projectImg);
            modalContent.appendChild(projectInfo);
            
            // Show modal
            modal.style.display = 'block';
            document.body.style.overflow = 'hidden'; // Prevent scrolling when modal is open
        });
    });
    
    // Close modal when X is clicked
    if (closeModal) {
        closeModal.addEventListener('click', () => {
            modal.style.display = 'none';
            document.body.style.overflow = 'auto'; // Re-enable scrolling
        });
    }
    
    // Close modal when clicking outside of modal content
    window.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.style.display = 'none';
            document.body.style.overflow = 'auto';
        }
    });
}

// Smooth scrolling for navigation links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function(e) {
        e.preventDefault();
        
        const targetId = this.getAttribute('href');
        const targetElement = document.querySelector(targetId);
        
        if (targetElement) {
            window.scrollTo({
                top: targetElement.offsetTop - 70, // Adjust for fixed navbar
                behavior: 'smooth'
            });
        }
    });
});

// Navbar scroll effect
window.addEventListener('scroll', function() {
    const navbar = document.getElementById('navbar');
    if (window.scrollY > 50) {
        navbar.style.boxShadow = '0 2px 10px rgba(0, 0, 0, 0.1)';
        navbar.style.background = 'rgba(255, 255, 255, 0.95)';
    } else {
        navbar.style.boxShadow = 'none';
        navbar.style.background = 'rgba(255, 255, 255, 0.95)';
    }
});