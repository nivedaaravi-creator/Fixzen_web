// Toasts
function ensureToastContainer() {
  let container = document.querySelector('.toast-container');
  if (!container) {
    container = document.createElement('div');
    container.className = 'toast-container';
    document.body.appendChild(container);
  }
  return container;
}

export function showToast(message, type = 'default', timeoutMs = 2500) {
  const container = ensureToastContainer();
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  requestAnimationFrame(() => toast.classList.add('show'));
  const remove = () => {
    toast.classList.remove('show');
    setTimeout(() => toast.remove(), 200);
  };
  if (timeoutMs > 0) setTimeout(remove, timeoutMs);
  toast.addEventListener('click', remove);
}

// Modals
export function openModal(id) {
  const backdrop = document.getElementById(id);
  if (backdrop) backdrop.classList.add('show');
}

export function closeModal(id) {
  const backdrop = document.getElementById(id);
  if (backdrop) backdrop.classList.remove('show');
}

// Theme Management
export function initTheme() {
  const savedTheme = localStorage.getItem('theme') || 'light';
  document.documentElement.setAttribute('data-theme', savedTheme);
  updateThemeIcon(savedTheme);
}

export function toggleTheme() {
  const currentTheme = document.documentElement.getAttribute('data-theme');
  const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', newTheme);
  localStorage.setItem('theme', newTheme);
  updateThemeIcon(newTheme);
  showToast(`Switched to ${newTheme} theme`, 'success');
}

function updateThemeIcon(theme) {
  const themeIcon = document.getElementById('theme-icon');
  if (themeIcon) {
    themeIcon.textContent = theme === 'dark' ? '☀️' : '🌙';
  }
}

// Chatbot functionality
export function toggleChatbot() {
  const chatbot = document.getElementById('chatbot');
  const isVisible = chatbot.style.display !== 'none';
  chatbot.style.display = isVisible ? 'none' : 'block';
  
  if (!isVisible) {
    const input = chatbot.querySelector('#chat-input');
    if (input) input.focus();
  }
}

export function sendChatMessage() {
  const input = document.getElementById('chat-input');
  const messages = document.getElementById('chat-messages');
  const message = input.value.trim();
  
  if (!message) return;
  
  // Add user message
  addChatMessage(message, 'user');
  input.value = '';
  
  // Simulate bot response
  setTimeout(() => {
    const response = getBotResponse(message);
    addChatMessage(response, 'bot');
  }, 1000);
}

function addChatMessage(message, sender) {
  const messages = document.getElementById('chat-messages');
  const messageDiv = document.createElement('div');
  messageDiv.className = `chat-message ${sender}`;
  messageDiv.innerHTML = `
    <div class="message-content">${message}</div>
    <div class="message-time">${new Date().toLocaleTimeString()}</div>
  `;
  messages.appendChild(messageDiv);
  messages.scrollTop = messages.scrollHeight;
}

function getBotResponse(message) {
  const responses = {
    'hello': 'Hi there! How can I help you with road maintenance today?',
    'crack': 'Our AI can detect cracks as small as 0.1mm! Would you like to try our crack detection system?',
    'healing': 'Our liquid healing technology uses biomaterials to repair cracks in 24 hours. It\'s eco-friendly!',
    'report': 'You can submit road quality reports through our form. This helps improve road conditions.',
    'help': 'I can assist with crack detection, liquid healing, reports, and analytics. What interests you?'
  };
  
  const lowerMessage = message.toLowerCase();
  for (const [key, response] of Object.entries(responses)) {
    if (lowerMessage.includes(key)) {
      return response;
    }
  }
  
  return 'Thanks for your message! Our team specializes in AI-powered road maintenance. How can I help you today?';
}

// Notification system
let notifications = [];

export function showNotification(title, message, type = 'info') {
  const notification = {
    id: Date.now(),
    title,
    message,
    type,
    timestamp: new Date()
  };
  
  notifications.unshift(notification);
  updateNotificationBadge();
  
  // Show toast for immediate feedback
  showToast(`${title}: ${message}`, type);
}

export function toggleNotifications() {
  const panel = document.getElementById('notifications-panel');
  const isVisible = panel.style.display !== 'none';
  panel.style.display = isVisible ? 'none' : 'block';
  
  if (!isVisible) {
    renderNotifications();
  }
}

function updateNotificationBadge() {
  const badge = document.getElementById('notification-badge');
  if (badge) {
    const unreadCount = notifications.length;
    badge.textContent = unreadCount > 99 ? '99+' : unreadCount;
    badge.style.display = unreadCount > 0 ? 'block' : 'none';
  }
}

function renderNotifications() {
  const container = document.getElementById('notifications-list');
  if (!container) return;
  
  container.innerHTML = notifications.length === 0 
    ? '<div class="no-notifications">No notifications yet</div>'
    : notifications.map(notif => `
        <div class="notification-item ${notif.type}">
          <div class="notification-header">
            <strong>${notif.title}</strong>
            <span class="notification-time">${formatTime(notif.timestamp)}</span>
          </div>
          <div class="notification-message">${notif.message}</div>
        </div>
      `).join('');
}

function formatTime(date) {
  const now = new Date();
  const diff = now - date;
  const minutes = Math.floor(diff / 60000);
  
  if (minutes < 1) return 'Just now';
  if (minutes < 60) return `${minutes}m ago`;
  if (minutes < 1440) return `${Math.floor(minutes / 60)}h ago`;
  return date.toLocaleDateString();
}

// Image upload preview
export function handleImageUpload(input) {
  const file = input.files[0];
  if (!file) return;
  
  const preview = document.getElementById('image-preview');
  const reader = new FileReader();
  
  reader.onload = function(e) {
    preview.innerHTML = `
      <img src="${e.target.result}" alt="Preview" style="max-width: 100%; height: auto; border-radius: 8px;">
      <div class="upload-info">
        <p><strong>File:</strong> ${file.name}</p>
        <p><strong>Size:</strong> ${(file.size / 1024 / 1024).toFixed(2)} MB</p>
        <p><strong>Type:</strong> ${file.type}</p>
      </div>
    `;
    preview.style.display = 'block';
  };
  
  reader.readAsDataURL(file);
}

// Auto-show Flask flash messages as toasts when present
document.addEventListener('DOMContentLoaded', () => {
  // Initialize theme
  initTheme();
  
  // Handle flash messages
  const flashNodes = document.querySelectorAll('[data-flash]');
  flashNodes.forEach(node => {
    const type = node.getAttribute('data-type') || 'default';
    const text = node.textContent?.trim();
    if (text) showToast(text, type);
    node.remove();
  });
  
  // Add sample notifications for demo
  setTimeout(() => {
    showNotification('System Update', 'New crack detection algorithm deployed', 'success');
  }, 2000);
  
  setTimeout(() => {
    showNotification('Maintenance Alert', 'Scheduled maintenance in 2 hours', 'warning');
  }, 5000);
  
  // Setup chat input enter key
  const chatInput = document.getElementById('chat-input');
  if (chatInput) {
    chatInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        sendChatMessage();
      }
    });
  }
});




