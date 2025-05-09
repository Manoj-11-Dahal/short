-- Create database if not exists
CREATE DATABASE IF NOT EXISTS portfolio;

-- Use the portfolio database
USE portfolio;

-- Create table for contact form submissions
CREATE TABLE IF NOT EXISTS contact_messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL,
    message TEXT NOT NULL,
    timestamp DATETIME NOT NULL
);

-- Create table for projects (optional)
CREATE TABLE IF NOT EXISTS projects (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(100) NOT NULL,
    description TEXT NOT NULL,
    image_url VARCHAR(255) NOT NULL,
    project_url VARCHAR(255),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insert sample project data (optional)
INSERT INTO projects (title, description, image_url, project_url) VALUES
('E-commerce Website', 'A fully responsive e-commerce platform with product filtering and secure checkout.', 'images/project1.jpg', '#'),
('Portfolio Template', 'A customizable portfolio template with smooth animations and responsive design.', 'images/project2.jpg', '#'),
('Blog Platform', 'A dynamic blog platform with content management system and user authentication.', 'images/project3.jpg', '#');