let currentLevel = null;
let userSession = null;
let isSubmitting = false;

async function initializePage() {
    try {
        const sessionData = await loadUserSession();
        if (!sessionData) {
            window.location.href = '/auth';
            return;
        }

        await checkAdminAccess();
        await loadCurrentLevel();
        await checkNotifications();
        
        setInterval(checkNotifications, 30000);
        
    } catch (error) {
        console.error('Failed to initialize page:', error);
        window.location.href = '/auth';
    }
}

async function loadUserSession() {
    try {
        const response = await fetch('/api/user/session', {
            headers: {
                'CSRFtok': getCookie('X-CSRF_COOKIE') || ''
            }
        });

        if (response.ok) {
            userSession = await response.json();
            return userSession;
        } else {
            return null;
        }
    } catch (error) {
        console.error('Failed to load user session:', error);
        return null;
    }
}

async function checkAdminAccess() {
    try {
        if (userSession && userSession.isAdmin) {
            const adminLink = document.getElementById('adminLink');
            const mobileAdminLink = document.getElementById('mobileAdminLink');
            if (adminLink) adminLink.style.display = 'inline-block';
            if (mobileAdminLink) mobileAdminLink.style.display = 'block';
        } else {
            const adminLink = document.getElementById('adminLink');
            const mobileAdminLink = document.getElementById('mobileAdminLink');
            if (adminLink) adminLink.style.display = 'none';
            if (mobileAdminLink) mobileAdminLink.style.display = 'none';
        }
    } catch (error) {
        console.error('Failed to check admin access:', error);
        const adminLink = document.getElementById('adminLink');
        const mobileAdminLink = document.getElementById('mobileAdminLink');
        if (adminLink) adminLink.style.display = 'none';
        if (mobileAdminLink) mobileAdminLink.style.display = 'none';
    }
}

async function loadCurrentLevel() {
    try {
        const response = await fetch('/api/user/current-level?' + Date.now(), {
            headers: {
                'CSRFtok': getCookie('X-CSRF_COOKIE') || '',
                'Cache-Control': 'no-cache'
            }
        });

        if (!response.ok) {
            throw new Error(`API returned status ${response.status}`);
        }

        const newLevel = await response.json();
        currentLevel = newLevel;
        updateLevelDisplay();
        
    } catch (error) {
        console.error('Failed to load current level:', error);
        handleLevelLoadError(error);
        throw error;
    }
}

function updateLevelDisplay() {
    const levelTitle = document.getElementById('levelTitle');
    if (levelTitle) {
        levelTitle.textContent = `Level ${currentLevel.number}`;
    }
    
    const existingDescription = document.getElementById('levelDescription');
    if (existingDescription) {
        existingDescription.remove();
    }
    

    if (currentLevel.mediaUrl) {
        const mediaContainer = document.getElementById('levelMedia');
        if (mediaContainer) {
            if (currentLevel.mediaType === 'image') {
                mediaContainer.innerHTML = `<img src="${currentLevel.mediaUrl}" alt="Level ${currentLevel.number}" style="max-width: 100%; height: auto; margin: 1rem 0; border-radius: 8px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">`;
            } else if (currentLevel.mediaType === 'video') {
                mediaContainer.innerHTML = `<video controls style="max-width: 100%; height: auto; margin: 1rem 0; border-radius: 8px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);"><source src="${currentLevel.mediaUrl}" type="video/mp4"></video>`;
            }
        }
    } else {
        const mediaContainer = document.getElementById('levelMedia');
        if (mediaContainer) {
            mediaContainer.innerHTML = '';
        }
    }
    
    const feedback = document.getElementById('feedback');
    if (feedback) {
        feedback.textContent = '';
    }
    
    const answerInput = document.getElementById('answerInput');
    if (answerInput) {
        answerInput.value = '';
        answerInput.focus();
    }
}

function handleLevelLoadError(error) {
    const levelTitle = document.getElementById('levelTitle');
    const levelDescription = document.getElementById('levelDescription');
    
    if (levelTitle) {
        levelTitle.textContent = 'Level Not Found';
    }
        
    if (!levelDescription) {
        levelDescription = document.createElement('div');
        levelDescription.id = 'levelDescription';
        levelDescription.style.cssText = 'margin-bottom: 2rem; text-align: center; color: var(--text-color); font-size: 1.1rem; line-height: 1.6;';
        
        const levelContent = document.getElementById('levelContent');
        if (levelContent) {
            levelContent.insertBefore(levelDescription, levelContent.firstChild);
        }
    }
    
    if (error.message.includes('401')) {
        levelDescription.textContent = 'Authentication required. Please log in again.';
        setTimeout(() => {
            window.location.href = '/auth';
        }, 2000);
    } else {
        levelDescription.textContent = 'Failed to load level content. Please try refreshing the page.';
    }
}

async function handleSubmit() {
    if (isSubmitting) {
        return;
    }
    
    const answerInput = document.getElementById('answerInput');
    const feedback = document.getElementById('feedback');
    let answer = answerInput.value.trim();
    
    if (!answer) {
        feedback.textContent = 'Please enter an answer.';
        feedback.style.color = '#dc3545';
        setTimeout(() => {
            feedback.textContent = '';
            feedback.style.color = 'var(--primary)';
        }, 3000);
        return;
    }

    // Guidelines-compliant answer formatting
    // Convert to lowercase, remove spaces, keep alphanumeric and special characters
    answer = answer.toLowerCase().replace(/\s+/g, '');
    
    // Validate answer format
    if (!answer) {
        feedback.textContent = 'Answer cannot be empty after formatting. Please enter a valid answer.';
        feedback.style.color = '#dc3545';
        setTimeout(() => {
            feedback.textContent = '';
            feedback.style.color = 'var(--primary)';
        }, 3000);
        return;
    }

    if (!currentLevel) {
        feedback.textContent = 'No level loaded. Please refresh the page.';
        feedback.style.color = '#dc3545';
        return;
    }

    isSubmitting = true;
    
    try {
        // Show formatted answer to user
        const originalAnswer = answerInput.value.trim();
        if (originalAnswer !== answer) {
            feedback.textContent = `Checking answer: "${answer}" (formatted from "${originalAnswer}")...`;
        } else {
            feedback.textContent = 'Checking answer...';
        }
        feedback.style.color = 'var(--primary)';
        
        const response = await fetch('/api/submit-answer', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'CSRFtok': getCookie('X-CSRF_COOKIE') || ''
            },
            body: JSON.stringify({
                levelId: currentLevel.id,
                answer: answer
            })
        });

        if (!response.ok) {
            if (response.status === 401) {
                feedback.textContent = 'Session expired. Redirecting to login...';
                feedback.style.color = '#dc3545';
                setTimeout(() => {
                    window.location.href = '/auth';
                }, 2000);
                return;
            }
            throw new Error(`Server error: ${response.status}`);
        }

        const result = await response.json();
        
        if (result.correct) {
            feedback.textContent = 'Correct! Loading next level...';
            feedback.style.color = '#28a745';
            
            setTimeout(() => {
                window.location.reload();
            }, 1500);
        } else {
            feedback.textContent = result.message || 'Incorrect answer. Try again.';
            feedback.style.color = '#dc3545';
            
            setTimeout(() => {
                feedback.textContent = '';
                feedback.style.color = 'var(--primary)';
                isSubmitting = false;
            }, 3000);
        }
    } catch (error) {
        console.error('Failed to submit answer:', error);
        feedback.textContent = 'Correct! Loading next level...';
        feedback.style.color = '#28a745';
        
        setTimeout(() => {
            window.location.reload();
        }, 1500);
    }
}

async function handleLogout() {
    try {
        await fetch('/api/auth/logout', { 
            method: 'POST',
            headers: {
                'CSRFtok': getCookie('X-CSRF_COOKIE') || ''
            }
        });
    } catch (error) {
        console.error('Logout failed:', error);
    } finally {
        window.location.href = '/auth';
    }
}

async function checkNotifications() {
    try {
        const response = await fetch('/api/notifications/unread-count', {
            headers: {
                'CSRFtok': getCookie('X-CSRF_COOKIE') || ''
            }
        });
        
        if (response.ok) {
            const data = await response.json();
            const notificationDot = document.getElementById('notificationDot');
            
            if (notificationDot) {
                if (data.count > 0) {
                    notificationDot.classList.add('show');
                } else {
                    notificationDot.classList.remove('show');
                }
            }
        }
    } catch (error) {
        console.error('Failed to check notifications:', error);
    }
}

document.addEventListener('DOMContentLoaded', function() {
    console.log('Index page loaded, initializing...');
    initializePage();
});