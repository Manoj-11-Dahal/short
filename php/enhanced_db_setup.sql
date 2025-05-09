-- Create database if not exists
CREATE DATABASE IF NOT EXISTS portfolio;

-- Use the portfolio database
USE portfolio;

-- Create table for contact form submissions
CREATE TABLE IF NOT EXISTS contact_messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL,
    subject VARCHAR(200) NOT NULL,
    message TEXT NOT NULL,
    timestamp DATETIME NOT NULL,
    is_read BOOLEAN DEFAULT FALSE
);

-- Create table for blog posts
CREATE TABLE IF NOT EXISTS blog_posts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    slug VARCHAR(200) NOT NULL UNIQUE,
    content TEXT NOT NULL,
    excerpt TEXT,
    featured_image VARCHAR(255),
    author_id INT,
    status ENUM('draft', 'published') DEFAULT 'draft',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX (slug),
    INDEX (status)
);

-- Create table for blog categories
CREATE TABLE IF NOT EXISTS blog_categories (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    slug VARCHAR(100) NOT NULL UNIQUE,
    INDEX (slug)
);

-- Create table for blog post categories (many-to-many relationship)
CREATE TABLE IF NOT EXISTS post_categories (
    post_id INT NOT NULL,
    category_id INT NOT NULL,
    PRIMARY KEY (post_id, category_id),
    FOREIGN KEY (post_id) REFERENCES blog_posts(id) ON DELETE CASCADE,
    FOREIGN KEY (category_id) REFERENCES blog_categories(id) ON DELETE CASCADE
);

-- Create table for users
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    auth0_id VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    name VARCHAR(100) NOT NULL,
    role ENUM('user', 'admin') DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX (auth0_id),
    INDEX (email)
);

-- Create table for projects
CREATE TABLE IF NOT EXISTS projects (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(100) NOT NULL,
    description TEXT NOT NULL,
    image_url VARCHAR(255) NOT NULL,
    project_url VARCHAR(255),
    technologies VARCHAR(255),
    featured BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Insert sample project data (optional)
INSERT INTO projects (title, description, image_url, project_url, technologies, featured) VALUES
('E-commerce Website', 'A fully responsive e-commerce platform with product filtering and secure checkout.', 'images/project1.jpg', '#', 'HTML, CSS, JavaScript, PHP, MySQL', TRUE),
('Portfolio Template', 'A customizable portfolio template with smooth animations and responsive design.', 'images/project2.jpg', '#', 'HTML, CSS, JavaScript', FALSE),
('Blog Platform', 'A dynamic blog platform with content management system and user authentication.', 'images/project3.jpg', '#', 'HTML, CSS, JavaScript, PHP, MySQL', TRUE);

-- Insert sample blog categories
INSERT INTO blog_categories (name, slug) VALUES
('Web Development', 'web-development'),
('UI/UX Design', 'ui-ux-design'),
('Programming', 'programming'),
('Career Advice', 'career-advice');