// Toast Notification System
function showToast(type, message) {
    const toast = document.getElementById('toastNotification');
    const toastIcon = document.getElementById('toastIcon');
    const toastMessage = document.getElementById('toastMessage');

    if (!toast) return;

    // Reset classes
    toast.className = 'toast';
    toastIcon.className = 'fa-solid';

    // Apply type class and icon
    if (type === 'success') {
        toast.classList.add('toast-success');
        toastIcon.classList.add('fa-circle-check');
    } else if (type === 'danger') {
        toast.classList.add('toast-danger');
        toastIcon.classList.add('fa-circle-xmark');
    } else if (type === 'warning') {
        toast.classList.add('toast-warning');
        toastIcon.classList.add('fa-triangle-exclamation');
    } else {
        toast.classList.add('toast-info');
        toastIcon.classList.add('fa-circle-info');
    }

    toastMessage.textContent = message;
    
    // Show toast
    toast.classList.remove('hidden');
    toast.classList.add('show');

    // Auto hide after 3.5 seconds
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => {
            toast.classList.add('hidden');
        }, 300);
    }, 3500);
}

// Modal Toggle Handlers
function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.remove('hidden');
        document.body.style.overflow = 'hidden'; // prevent background scroll
    }
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.add('hidden');
        document.body.style.overflow = ''; // restore scroll
    }
}

// Security Toggle Handler
document.addEventListener('DOMContentLoaded', () => {
    const toggleBtn = document.getElementById('securityToggleBtn');
    if (toggleBtn) {
        toggleBtn.addEventListener('click', async () => {
            try {
                const response = await fetch('/api/toggle_security', {
                    method: 'POST'
                });
                const data = await response.json();
                
                if (data.success) {
                    const statusText = data.security_mode ? '보안 모드가 활성화되었습니다. (시큐어 코딩 보호 가동)' : '보안 모드가 해제되고 취약점이 오픈되었습니다.';
                    const type = data.security_mode ? 'success' : 'warning';
                    
                    showToast(type, statusText);
                    
                    // Reload after 1.2s to reflect changes on current page
                    setTimeout(() => {
                        window.location.reload();
                    }, 1200);
                }
            } catch (e) {
                showToast('danger', '보안 상태 전환 중 통신 오류가 발생했습니다.');
            }
        });
    }
    
    // Close modals on clicking outside modal-content
    window.addEventListener('click', (e) => {
        if (e.target.classList.contains('modal')) {
            e.target.classList.add('hidden');
            document.body.style.overflow = '';
        }
    });
});
