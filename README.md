# Portfolio Website

A responsive portfolio website with interactive animations, PHP/MySQL backend, and modern design.

## Features

- **Responsive Design**: Works seamlessly on mobile, tablet, and desktop devices
- **Interactive Animations**: Includes scroll-triggered animations, hover effects, and glowing elements
- **PHP/MySQL Backend**: Stores contact form submissions and project data
- **Five Main Sections**: Home, About, Projects, Contact, and Footer
- **Accessibility**: Keyboard navigation support and proper image alt text
- **Security**: Form validation and SQL injection prevention

## Project Structure

```
├── index.html          # Main HTML file
├── css/
│   └── style.css       # CSS styles and animations
├── js/
│   └── main.js         # JavaScript for interactivity
├── php/
│   ├── contact.php     # Contact form handler
│   ├── load_projects.php # Dynamic project loader
│   └── db_setup.sql    # Database setup script
├── images/             # Project and site images (not included)
└── README.md           # This file
```

## Setup Instructions

### Prerequisites

- Web server with PHP support (e.g., XAMPP, WAMP, or MAMP)
- MySQL database

### Database Setup

1. Start your local web server and MySQL service
2. Create a new database named `portfolio` (or use the provided SQL script)
3. Import the `php/db_setup.sql` file to set up the required tables

### Configuration

1. If needed, update the database connection details in `php/contact.php` and `php/load_projects.php`:
   ```php
   $host = 'localhost';
   $dbname = 'portfolio';
   $username = 'root'; // Change if needed
   $password = ''; // Change if needed
   ```

2. Place the entire project folder in your web server's document root (e.g., `htdocs` for XAMPP)

### Running the Website

1. Start your web server (Apache and MySQL)
2. Navigate to `http://localhost/kko` in your web browser (adjust the path if needed)

## Customization

### Adding Projects

You can add projects in two ways:

1. **Database Method**: Add entries to the `projects` table in the database
2. **HTML Method**: Add project cards directly in the `index.html` file

### Changing Colors

The color scheme can be modified by editing the CSS variables in `css/style.css`:

```css
:root {
    --primary-color: #2a2a72;
    --secondary-color: #009ffd;
    --accent-color: #00d4ff;
    --dark-color: #1a1a2e;
    --light-color: #f8f9fa;
    --transition: all 0.3s ease;
}
```

## Browser Compatibility

Tested and working in:
- Chrome (latest)
- Firefox (latest)
- Safari (latest)
- Edge (latest)

## Credits

- Particles.js for background effects
- Font Awesome for icons

## License

This project is available for personal and commercial use.