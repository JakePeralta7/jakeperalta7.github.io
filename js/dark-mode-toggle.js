// Dark mode toggle functionality
(function() {
  'use strict';

  // Check for saved theme preference or default to light mode
  const currentTheme = localStorage.getItem('theme') || 'light';
  
  // Apply the theme on page load
  document.documentElement.setAttribute('data-theme', currentTheme);

  // Wait for DOM to be fully loaded
  document.addEventListener('DOMContentLoaded', function() {
    const toggleButton = document.getElementById('dark-mode-toggle');
    
    if (!toggleButton) {
      console.warn('Dark mode toggle button not found');
      return;
    }

    // Set initial button state
    updateToggleButton(currentTheme);

    // Toggle theme on button click
    toggleButton.addEventListener('click', function() {
      const currentTheme = document.documentElement.getAttribute('data-theme');
      const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
      
      document.documentElement.setAttribute('data-theme', newTheme);
      localStorage.setItem('theme', newTheme);
      updateToggleButton(newTheme);
    });
  });

  function updateToggleButton(theme) {
    const toggleButton = document.getElementById('dark-mode-toggle');
    if (!toggleButton) return;
    
    if (theme === 'dark') {
      toggleButton.innerHTML = '☀️';
      toggleButton.setAttribute('aria-label', 'Switch to light mode');
      toggleButton.setAttribute('title', 'Switch to light mode');
    } else {
      toggleButton.innerHTML = '🌙';
      toggleButton.setAttribute('aria-label', 'Switch to dark mode');
      toggleButton.setAttribute('title', 'Switch to dark mode');
    }
  }
})();
