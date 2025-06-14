/**
 * Pentester Analysis Tool - Enhanced JavaScript
 * Handles client-side functionality with modern UI enhancements
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    const tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Initialize tab functionality with smooth transitions
    const tabElms = document.querySelectorAll('button[data-bs-toggle="tab"]');
    tabElms.forEach(function(tabElm) {
        tabElm.addEventListener('shown.bs.tab', function (event) {
            // Actions to perform when a tab is shown
            const targetId = event.target.getAttribute('data-bs-target').substring(1);
            localStorage.setItem('activeTab', targetId);
            
            // Add animation to newly shown tab
            const tabPane = document.getElementById(targetId);
            if (tabPane) {
                tabPane.classList.add('tab-animation');
                setTimeout(() => {
                    tabPane.classList.remove('tab-animation');
                }, 500);
            }
        });
    });
    
    // Load last active tab if available
    const lastActiveTab = localStorage.getItem('activeTab');
    if (lastActiveTab) {
        const tabEl = document.querySelector(`[data-bs-target="#${lastActiveTab}"]`);
        if (tabEl) {
            new bootstrap.Tab(tabEl).show();
        }
    }
    
    // Enhanced file upload with preview
    const fileInput = document.getElementById('scan_files');
    if (fileInput) {
        fileInput.addEventListener('change', function(e) {
            const fileNameDisplay = document.getElementById('fileNameDisplay');
            const files = Array.from(e.target.files);
            
            if (files.length > 0) {
                // Create styled file display with animation
                const fileNames = files.map((file, index) => {
                    // Get appropriate icon based on file extension
                    const ext = file.name.split('.').pop().toLowerCase();
                    let icon = 'fa-file-alt';
                    
                    if (['txt', 'log'].includes(ext)) icon = 'fa-file-alt';
                    else if (['xml'].includes(ext)) icon = 'fa-file-code';
                    else if (['json'].includes(ext)) icon = 'fa-file-code';
                    else if (['nmap', 'gnmap'].includes(ext)) icon = 'fa-network-wired';
                    else if (['csv'].includes(ext)) icon = 'fa-file-csv';
                    
                    // Add animation delay based on index
                    const delay = index * 100;
                    
                    return `<span class="badge bg-dark text-light me-2 mb-2 p-2 file-badge" style="animation-delay: ${delay}ms">
                        <i class="fas ${icon} me-2"></i>${file.name} 
                        <small class="text-muted">(${(file.size/1024).toFixed(1)} KB)</small>
                        <button type="button" class="btn-close btn-close-white ms-2 file-remove" aria-label="Remove"></button>
                    </span>`;
                }).join('');
                
                if (fileNameDisplay) {
                    fileNameDisplay.innerHTML = fileNames;
                    fileNameDisplay.classList.remove('d-none');
                    
                    // Add event listeners to remove buttons
                    document.querySelectorAll('.file-remove').forEach((btn, index) => {
                        btn.addEventListener('click', function(e) {
                            e.preventDefault();
                            e.stopPropagation();
                            
                            // Create a new FileList without the removed file
                            const dt = new DataTransfer();
                            const { files } = fileInput;
                            
                            for (let i = 0; i < files.length; i++) {
                                if (i !== index) {
                                    dt.items.add(files[i]);
                                }
                            }
                            
                            fileInput.files = dt.files;
                            
                            // Trigger change event to update display
                            const event = new Event('change');
                            fileInput.dispatchEvent(event);
                        });
                    });
                }
            } else {
                if (fileNameDisplay) {
                    fileNameDisplay.innerHTML = '';
                    fileNameDisplay.classList.add('d-none');
                }
            }
        });
    }
    
    // Terminal text effect and syntax highlighting
    const scanInput = document.getElementById('scan_input');
    if (scanInput) {
        // Blinking cursor effect
        const cursorSpan = document.createElement('span');
        cursorSpan.className = 'cursor-blink';
        cursorSpan.textContent = '|';
        
        scanInput.addEventListener('focus', function() {
            this.classList.add('active');
            
            // Only remove placeholder when user starts typing
            this.addEventListener('input', function() {
                if (this.value.length > 0) {
                    this.setAttribute('placeholder', '');
                } else {
                    this.setAttribute('placeholder', 'Paste your nmap, nikto, sqlmap, gobuster, or other scan output here...');
                }
            });
        });
        
        scanInput.addEventListener('blur', function() {
            this.classList.remove('active');
        });
    }
    
    // Settings form handling with visual feedback
    const saveSettingsButton = document.getElementById('saveSettings');
    if (saveSettingsButton) {
        saveSettingsButton.addEventListener('click', function() {
            const aiProvider = document.getElementById('aiProvider').value;
            const apiKey = document.getElementById('openai_api_key').value;
            const includeExploits = document.getElementById('includeExploits').checked;
            const saveScanHistory = document.getElementById('saveScanHistory').checked;
            const enableStreaming = document.getElementById('enableStreaming').checked;
            const autoEnrichCVEs = document.getElementById('autoEnrichCVEs').checked;
            
            // Save settings to localStorage
            localStorage.setItem('aiProvider', aiProvider);
            localStorage.setItem('includeExploits', includeExploits);
            localStorage.setItem('saveScanHistory', saveScanHistory);
            localStorage.setItem('enableStreaming', enableStreaming);
            localStorage.setItem('autoEnrichCVEs', autoEnrichCVEs);
            
            // Visual feedback - button loading state
            const originalText = saveSettingsButton.innerHTML;
            saveSettingsButton.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Saving...';
            saveSettingsButton.disabled = true;
            
            // If API key is provided, send it to the server
            if (apiKey) {
                fetch('/update_api_key', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        api_key: apiKey,
                        provider: aiProvider
                    })
                })
                .then(response => response.json())
                .then(data => {
                    // Reset button
                    saveSettingsButton.innerHTML = originalText;
                    saveSettingsButton.disabled = false;
                    
                    if (data.success) {
                        showNotification('API key and settings saved successfully', 'success');
                    } else {
                        showNotification('Error saving API key: ' + data.message, 'error');
                    }
                })
                .catch(error => {
                    // Reset button
                    saveSettingsButton.innerHTML = originalText;
                    saveSettingsButton.disabled = false;
                    showNotification('Error: ' + error.message, 'error');
                });
            } else {
                // Reset button after short delay for visual feedback
                setTimeout(() => {
                    saveSettingsButton.innerHTML = originalText;
                    saveSettingsButton.disabled = false;
                    showNotification('Settings saved (browser only)', 'info');
                }, 800);
            }
        });
        
        // Load settings
        const loadSettings = function() {
            const aiProvider = localStorage.getItem('aiProvider');
            const includeExploits = localStorage.getItem('includeExploits') === 'true';
            const saveScanHistory = localStorage.getItem('saveScanHistory') !== 'false'; // Default to true
            const enableStreaming = localStorage.getItem('enableStreaming') === 'true';
            const autoEnrichCVEs = localStorage.getItem('autoEnrichCVEs') !== 'false'; // Default to true
            
            if (aiProvider && document.getElementById('aiProvider')) document.getElementById('aiProvider').value = aiProvider;
            if (document.getElementById('includeExploits')) document.getElementById('includeExploits').checked = includeExploits;
            if (document.getElementById('saveScanHistory')) document.getElementById('saveScanHistory').checked = saveScanHistory;
            if (document.getElementById('enableStreaming')) document.getElementById('enableStreaming').checked = enableStreaming;
            if (document.getElementById('autoEnrichCVEs')) document.getElementById('autoEnrichCVEs').checked = autoEnrichCVEs;
            
            // Fetch current API key status
            fetch('/check_api_key')
            .then(response => response.json())
            .then(data => {
                if (data.has_key) {
                    document.getElementById('openai_api_key').placeholder = '*** API key is set ***';
                }
            });
        };
        
        // Load settings when DOM is ready
        loadSettings();
    }
    
    // API key visibility toggle with animation
    window.toggleApiKeyVisibility = function() {
        const apiKeyInput = document.getElementById('openai_api_key');
        const toggleButton = document.querySelector('button[onclick="toggleApiKeyVisibility()"] i');
        
        if (apiKeyInput.type === 'password') {
            apiKeyInput.type = 'text';
            toggleButton.classList.remove('fa-eye');
            toggleButton.classList.add('fa-eye-slash');
        } else {
            apiKeyInput.type = 'password';
            toggleButton.classList.remove('fa-eye-slash');
            toggleButton.classList.add('fa-eye');
        }
    };
    
    // Enhanced copy buttons for code blocks
    const codeBlocks = document.querySelectorAll('.code-block');
    codeBlocks.forEach(block => {
        const copyBtn = block.querySelector('.copy-btn');
        if (copyBtn) {
            copyBtn.addEventListener('click', function() {
                const code = block.querySelector('code').textContent;
                navigator.clipboard.writeText(code).then(() => {
                    // Visual feedback
                    const originalText = copyBtn.innerHTML;
                    copyBtn.innerHTML = '<i class="fas fa-check"></i> Copied!';
                    copyBtn.classList.add('copy-success');
                    
                    setTimeout(() => {
                        copyBtn.innerHTML = originalText;
                        copyBtn.classList.remove('copy-success');
                    }, 2000);
                }).catch(err => {
                    console.error('Could not copy text: ', err);
                    
                    // Error feedback
                    const originalText = copyBtn.innerHTML;
                    copyBtn.innerHTML = '<i class="fas fa-times"></i> Failed!';
                    copyBtn.classList.add('copy-error');
                    
                    setTimeout(() => {
                        copyBtn.innerHTML = originalText;
                        copyBtn.classList.remove('copy-error');
                    }, 2000);
                });
            });
        }
    });
    
    // Results export functionality with progress indicator
    const exportBtn = document.getElementById('exportResults');
    if (exportBtn) {
        exportBtn.addEventListener('click', function() {
            // Visual feedback - button loading state
            const originalText = exportBtn.innerHTML;
            exportBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Exporting...';
            exportBtn.disabled = true;
            
            // Get results data from hidden element or from page content
            let resultsData;
            const resultDataElem = document.getElementById('result-data');
            
            if (resultDataElem && resultDataElem.textContent) {
                resultsData = JSON.parse(resultDataElem.textContent);
            } else {
                // Try to extract data from the current page structure if no hidden element
                resultsData = extractResultsFromPage();
            }
            
            if (resultsData) {
                // Format results nicely
                const dataStr = JSON.stringify(resultsData, null, 2);
                const blob = new Blob([dataStr], {type: 'application/json'});
                const url = URL.createObjectURL(blob);
                
                // Create title for file from scan title or timestamp
                const scanTitle = resultsData.metadata?.scan_title || 'scan-results';
                const timestamp = new Date().toISOString().slice(0,10);
                const fileName = `${scanTitle.replace(/[^a-z0-9]/gi, '-').toLowerCase()}-${timestamp}.json`;
                
                // Create download link
                const a = document.createElement('a');
                a.href = url;
                a.download = fileName;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                
                // Reset button and show success notification
                setTimeout(() => {
                    exportBtn.innerHTML = originalText;
                    exportBtn.disabled = false;
                    showNotification('Results exported successfully', 'success');
                }, 800);
            } else {
                // Reset button and show error
                exportBtn.innerHTML = originalText;
                exportBtn.disabled = false;
                showNotification('Error: Could not extract results data', 'error');
            }
        });
    }
    
    // Helper function to extract results from page content if needed
    function extractResultsFromPage() {
        try {
            // This would need to be customized based on your page structure
            // Just a basic example that assumes specific page elements
            const results = {
                metadata: {},
                ports_and_services: [],
                web_directories: [],
                vulnerabilities: [],
                // other categories...
            };
            
            // Extract metadata
            const titleElement = document.querySelector('h5:contains("Results:")');
            if (titleElement) {
                results.metadata.scan_title = titleElement.textContent.replace('Results:', '').trim();
            }
            
            // You would need to add more code to extract all the data categories
            // from their respective page elements
            
            return results;
        } catch (e) {
            console.error('Error extracting results from page:', e);
            return null;
        }
    }
    
    // History management functions
    const deleteHistoryButtons = document.querySelectorAll('.delete-history-item');
    if (deleteHistoryButtons.length > 0) {
        deleteHistoryButtons.forEach(button => {
            button.addEventListener('click', function(e) {
                e.preventDefault();
                const sessionId = this.getAttribute('data-session-id');
                const historyItem = this.closest('.history-item');
                
                if (confirm('Are you sure you want to delete this history item?')) {
                    // Visual feedback
                    button.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
                    button.disabled = true;
                    
                    fetch(`/delete_history/${sessionId}`, {
                        method: 'POST'
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            // Animate removal
                            historyItem.style.height = historyItem.offsetHeight + 'px';
                            historyItem.classList.add('removing');
                            
                            setTimeout(() => {
                                historyItem.style.height = '0';
                                historyItem.style.opacity = '0';
                                historyItem.style.margin = '0';
                                historyItem.style.padding = '0';
                                
                                setTimeout(() => {
                                    historyItem.remove();
                                    
                                    // Check if no items left
                                    const remainingItems = document.querySelectorAll('.history-item');
                                    if (remainingItems.length === 0) {
                                        const emptyState = document.createElement('div');
                                        emptyState.className = 'text-center py-5';
                                        emptyState.innerHTML = `
                                            <i class="fas fa-history fa-3x mb-3" style="color: var(--accent-secondary);"></i>
                                            <p>No analysis history found</p>
                                        `;
                                        document.getElementById('history-list').appendChild(emptyState);
                                    }
                                }, 300);
                            }, 100);
                        } else {
                            button.innerHTML = '<i class="fas fa-trash"></i>';
                            button.disabled = false;
                            showNotification('Error: ' + data.error, 'error');
                        }
                    })
                    .catch(error => {
                        button.innerHTML = '<i class="fas fa-trash"></i>';
                        button.disabled = false;
                        showNotification('Error: ' + error.message, 'error');
                    });
                }
            });
        });
    }
    
    // Clear all history button
    const clearHistoryButton = document.getElementById('clearAllHistory');
    if (clearHistoryButton) {
        clearHistoryButton.addEventListener('click', function(e) {
            e.preventDefault();
            
            if (confirm('Are you sure you want to delete ALL history items? This cannot be undone.')) {
                // Visual feedback
                const originalText = clearHistoryButton.innerHTML;
                clearHistoryButton.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Clearing...';
                clearHistoryButton.disabled = true;
                
                fetch('/clear_history', {
                    method: 'POST'
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        // Remove all history items with animation
                        const historyItems = document.querySelectorAll('.history-item');
                        historyItems.forEach((item, index) => {
                            setTimeout(() => {
                                item.style.height = item.offsetHeight + 'px';
                                item.classList.add('removing');
                                
                                setTimeout(() => {
                                    item.style.height = '0';
                                    item.style.opacity = '0';
                                    item.style.margin = '0';
                                    item.style.padding = '0';
                                    
                                    setTimeout(() => {
                                        item.remove();
                                        
                                        // If last item, add empty state
                                        if (index === historyItems.length - 1) {
                                            const emptyState = document.createElement('div');
                                            emptyState.className = 'text-center py-5';
                                            emptyState.innerHTML = `
                                                <i class="fas fa-history fa-3x mb-3" style="color: var(--accent-secondary);"></i>
                                                <p>No analysis history found</p>
                                            `;
                                            document.getElementById('history-list').appendChild(emptyState);
                                            
                                            // Reset button
                                            clearHistoryButton.innerHTML = originalText;
                                            clearHistoryButton.disabled = false;
                                            
                                            showNotification(`Successfully cleared ${data.count} history items`, 'success');
                                        }
                                    }, 300);
                                }, 100);
                            }, index * 50);  // Stagger the removals
                        });
                    } else {
                        clearHistoryButton.innerHTML = originalText;
                        clearHistoryButton.disabled = false;
                        showNotification('Error: ' + data.error, 'error');
                    }
                })
                .catch(error => {
                    clearHistoryButton.innerHTML = originalText;
                    clearHistoryButton.disabled = false;
                    showNotification('Error: ' + error.message, 'error');
                });
            }
        });
    }
    
    // Initialize syntax highlighting
    document.querySelectorAll('pre code').forEach((el) => {
        hljs.highlightElement(el);
    });
    
    // Enhanced notification system
    window.showNotification = function(message, type = 'info') {
        // Create notification container if it doesn't exist
        let notificationContainer = document.getElementById('notification-container');
        
        if (!notificationContainer) {
            notificationContainer = document.createElement('div');
            notificationContainer.id = 'notification-container';
            notificationContainer.className = 'notification-container';
            document.body.appendChild(notificationContainer);
        }
        
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        
        // Icons for different notification types
        let icon = 'fa-info-circle';
        if (type === 'success') icon = 'fa-check-circle';
        if (type === 'error') icon = 'fa-exclamation-triangle';
        if (type === 'warning') icon = 'fa-exclamation-circle';
        
        notification.innerHTML = `
            <div class="notification-content">
                <div class="notification-icon">
                    <i class="fas ${icon}"></i>
                </div>
                <div class="notification-message">${message}</div>
                <div class="notification-close">
                    <i class="fas fa-times"></i>
                </div>
            </div>
            <div class="notification-progress"></div>
        `;
        
        // Add notification to container
        notificationContainer.appendChild(notification);
        
        // Add click listener for close button
        const closeBtn = notification.querySelector('.notification-close');
        closeBtn.addEventListener('click', () => {
            notification.classList.add('notification-hiding');
            setTimeout(() => {
                notification.remove();
            }, 300);
        });
        
        // Auto-dismiss after 5 seconds
        const progressBar = notification.querySelector('.notification-progress');
        progressBar.style.animationDuration = '5s';
        
        setTimeout(() => {
            notification.classList.add('notification-hiding');
            setTimeout(() => {
                notification.remove();
            }, 300);
        }, 5000);
    };
    
    // Add animation to page load
    document.querySelectorAll('.cyber-card').forEach((card, index) => {
        // Delay each card slightly for a cascade effect
        setTimeout(() => {
            card.classList.add('fade-in-up');
        }, index * 100);
    });
});

// Extend jQuery-like selectors for plain JS
if (!Element.prototype.matches) {
    Element.prototype.matches = Element.prototype.msMatchesSelector || Element.prototype.webkitMatchesSelector;
}

if (!Element.prototype.closest) {
    Element.prototype.closest = function(s) {
        var el = this;
        do {
            if (el.matches(s)) return el;
            el = el.parentElement || el.parentNode;
        } while (el !== null && el.nodeType === 1);
        return null;
    };
}