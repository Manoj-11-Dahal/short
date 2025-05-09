// Theme Toggle Functionality

document.addEventListener('DOMContentLoaded', function() {
    // Get theme toggle button
    const themeToggle = document.getElementById('theme-toggle');
    const themeIcon = themeToggle.querySelector('i');
    
    // Check for saved theme preference or use default
    const currentTheme = localStorage.getItem('theme') || 'light';
    
    // Apply saved theme on page load
    if (currentTheme === 'dark') {
        document.documentElement.setAttribute('data-theme', 'dark');
        themeIcon.classList.replace('fa-moon', 'fa-sun');
    }
    
    // Toggle theme when button is clicked
    themeToggle.addEventListener('click', function() {
        // Check current theme
        const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
        
        // Add transition classes to body for smooth transition
        document.body.classList.add('theme-transition');
        document.body.classList.add('theme-transition-active');
        document.body.classList.add('theme-transition-animation');
        
        // Toggle theme
        if (currentTheme === 'light') {
            // Switch to dark theme
            document.documentElement.setAttribute('data-theme', 'dark');
            localStorage.setItem('theme', 'dark');
            themeIcon.classList.replace('fa-moon', 'fa-sun');
            
            // Add animation to theme toggle
            themeToggle.classList.add('pulse');
            setTimeout(() => {
                themeToggle.classList.remove('pulse');
            }, 1000);
        } else {
            // Switch to light theme
            document.documentElement.setAttribute('data-theme', 'light');
            localStorage.setItem('theme', 'light');
            themeIcon.classList.replace('fa-sun', 'fa-moon');
            
            // Add animation to theme toggle
            themeToggle.classList.add('pulse');
            setTimeout(() => {
                themeToggle.classList.remove('pulse');
            }, 1000);
        }
        
        // Remove transition classes after animation completes
        setTimeout(() => {
            document.body.classList.remove('theme-transition-active');
            document.body.classList.remove('theme-transition-animation');
        }, 800);
        setTimeout(() => {
            document.body.classList.remove('theme-transition');
        }, 1000);
    });
    
    // Initialize animations for elements with glow effect
    initGlowEffects();
    
    // Initialize skill bar animations
    initSkillBars();
});

// Initialize glow effects
function initGlowEffects() {
    const glowElements = document.querySelectorAll('.glow-effect');
    
    glowElements.forEach(element => {
        element.addEventListener('mouseenter', function() {
            this.classList.add('active-glow');
        });
        
        element.addEventListener('mouseleave', function() {
            this.classList.remove('active-glow');
        });
    });
    
    // Add floating animation to selected elements
    const floatElements = document.querySelectorAll('.profile-image, .project-card');
    floatElements.forEach(element => {
        element.classList.add('float');
    });
    
    // Add pulse animation to buttons
    const pulseElements = document.querySelectorAll('.btn');
    pulseElements.forEach(element => {
        element.addEventListener('mouseenter', function() {
            this.classList.add('pulse');
        });
        
        element.addEventListener('mouseleave', function() {
            this.classList.remove('pulse');
        });
    });
}

// Initialize skill bar animations
function initSkillBars() {
    const skillLevels = document.querySelectorAll('.skill-level');
    
    // Set skill levels based on data-level attribute
    skillLevels.forEach(skill => {
        const level = skill.getAttribute('data-level');
        skill.style.width = level;
        
        // Add animation class
        setTimeout(() => {
            skill.classList.add('animated');
        }, 300);
    });
}