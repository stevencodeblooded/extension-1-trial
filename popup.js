/**
 * SemrushToolz Ultimate - Popup Script
 * Handles popup interface and communication with background script
 */

class SemrushPopup {
  constructor() {
    this.elements = {};
    this.state = {
      isLoading: false,
      lastUpdate: null,
    };

    this.init();
  }

  /**
   * Initialize popup
   */
  async init() {
    // Get DOM elements
    this.getElements();

    // Setup event listeners
    this.setupEventListeners();

    // Load initial data
    await this.loadStatus();

    // Setup auto-refresh
    this.setupAutoRefresh();
  }

  /**
   * Get DOM elements
   */
  getElements() {
    this.elements = {
      statusIndicator: document.getElementById("statusIndicator"),
      statusValue: document.getElementById("statusValue"),
      lastSyncValue: document.getElementById("lastSyncValue"),
      rulesCountValue: document.getElementById("rulesCountValue"),
      syncButton: document.getElementById("syncButton"),
      settingsButton: document.getElementById("settingsButton"),
      statusMessage: document.getElementById("statusMessage"),
    };
  }

  /**
   * Setup event listeners
   */
  setupEventListeners() {
    // Sync button
    if (this.elements.syncButton) {
      this.elements.syncButton.addEventListener(
        "click",
        this.handleSyncClick.bind(this)
      );
    }

    // Settings button
    if (this.elements.settingsButton) {
      this.elements.settingsButton.addEventListener(
        "click",
        this.handleSettingsClick.bind(this)
      );
    }

    // Handle popup close
    window.addEventListener("beforeunload", this.handlePopupClose.bind(this));
  }

  /**
   * Load status from background script
   */
  async loadStatus() {
    try {
      const response = await this.sendMessage({ action: "getStatus" });

      if (response.success) {
        this.updateStatus(response.data);
      } else {
        this.showError("Failed to load status");
      }
    } catch (error) {
      console.error("Error loading status:", error);
      this.showError("Error connecting to extension");
    }
  }

  /**
   * Update status display
   */
  updateStatus(data) {
    // Update status indicator
    if (data.isAuthenticated) {
      this.setStatus("active", "Active");
      this.elements.statusMessage.textContent =
        "Extension is running and protecting your browsing";
    } else {
      this.setStatus("inactive", "Inactive");
      this.elements.statusMessage.textContent = "Authentication required";
    }

    // Update last sync
    if (data.lastSync) {
      this.elements.lastSyncValue.textContent = this.formatDate(
        new Date(data.lastSync)
      );
    } else {
      this.elements.lastSyncValue.textContent = "Never";
    }

    // Update rules count
    this.elements.rulesCountValue.textContent = data.rulesCount || 0;

    this.state.lastUpdate = Date.now();
  }

  /**
   * Set status indicator
   */
  setStatus(status, text) {
    this.elements.statusIndicator.className = `status-indicator ${status}`;
    this.elements.statusValue.textContent = text;
    this.elements.statusValue.className = `value ${status}`;
  }

  /**
   * Handle sync button click
   */
  async handleSyncClick() {
    if (this.state.isLoading) return;

    this.setLoading(true);

    try {
      // Add timeout to prevent hanging
      const response = await Promise.race([
        this.sendMessage({ action: "syncRules" }),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error("Sync timeout")), 30000)
        ),
      ]);

      if (response && response.success) {
        this.showSuccess("Rules synchronized successfully");
        await this.loadStatus(); // Refresh status
      } else {
        // Even if response is undefined, check if sync actually worked
        setTimeout(async () => {
          const status = await this.sendMessage({ action: "getStatus" });
          if (status && status.data && status.data.lastSync) {
            // If lastSync is recent, sync was probably successful
            const lastSync = new Date(status.data.lastSync);
            const now = new Date();
            if (now - lastSync < 60000) {
              // Less than 1 minute ago
              this.showSuccess("Rules synchronized successfully");
              await this.loadStatus();
              return;
            }
          }
          this.showError("Failed to sync rules");
        }, 1000);
      }
    } catch (error) {
      console.error("Error syncing rules:", error);

      // Check if sync actually succeeded despite the error
      if (error.message === "Sync timeout") {
        // Give it a moment, then check status
        setTimeout(async () => {
          try {
            const status = await this.sendMessage({ action: "getStatus" });
            if (status && status.data && status.data.lastSync) {
              const lastSync = new Date(status.data.lastSync);
              const now = new Date();
              if (now - lastSync < 60000) {
                // Less than 1 minute ago
                this.showSuccess("Rules synchronized successfully");
                await this.loadStatus();
                return;
              }
            }
            this.showError("Sync completed but response timeout");
          } catch (statusError) {
            this.showError("Error syncing rules");
          }
        }, 2000);
      } else {
        this.showError("Error syncing rules");
      }
    } finally {
      this.setLoading(false);
    }
  }

  /**
   * Handle settings button click
   */
  async handleSettingsClick() {
    try {
      // Open options page or settings
      chrome.runtime.openOptionsPage?.() ||
        chrome.tabs.create({ url: chrome.runtime.getURL("options.html") });
    } catch (error) {
      console.error("Error opening settings:", error);
    }
  }

  /**
   * Handle popup close
   */
  handlePopupClose() {
    // Cleanup any ongoing operations
    this.setLoading(false);
  }

  /**
   * Set loading state
   */
  setLoading(isLoading) {
    this.state.isLoading = isLoading;

    if (this.elements.syncButton) {
      const buttonText = this.elements.syncButton.querySelector(".button-text");
      const loader = this.elements.syncButton.querySelector(".loader");

      if (isLoading) {
        this.elements.syncButton.disabled = true;
        buttonText.style.opacity = "0";
        loader.classList.remove("hidden");
      } else {
        this.elements.syncButton.disabled = false;
        buttonText.style.opacity = "1";
        loader.classList.add("hidden");
      }
    }
  }

  /**
   * Show success message
   */
  showSuccess(message) {
    this.showMessage(message, "success");
  }

  /**
   * Show error message
   */
  showError(message) {
    this.showMessage(message, "error");
  }

  /**
   * Show message with auto-hide
   */
  showMessage(message, type = "info") {
    const originalMessage = this.elements.statusMessage.textContent;
    const originalClass = this.elements.statusMessage.className;

    this.elements.statusMessage.textContent = message;
    this.elements.statusMessage.className = `status-message ${type}`;

    // Auto-hide after 3 seconds
    setTimeout(() => {
      this.elements.statusMessage.textContent = originalMessage;
      this.elements.statusMessage.className = originalClass;
    }, 3000);
  }

  /**
   * Format date for display
   */
  formatDate(date) {
    const now = new Date();
    const diff = Math.floor((now - date) / 1000);

    if (diff < 60) {
      return "Just now";
    } else if (diff < 3600) {
      const minutes = Math.floor(diff / 60);
      return `${minutes} minute${minutes > 1 ? "s" : ""} ago`;
    } else if (diff < 86400) {
      const hours = Math.floor(diff / 3600);
      return `${hours} hour${hours > 1 ? "s" : ""} ago`;
    } else {
      const days = Math.floor(diff / 86400);
      return `${days} day${days > 1 ? "s" : ""} ago`;
    }
  }

  /**
   * Setup auto-refresh
   */
  setupAutoRefresh() {
    // Refresh status every 30 seconds
    setInterval(async () => {
      if (!this.state.isLoading) {
        await this.loadStatus();
      }
    }, 30000);
  }

  /**
   * Send message to background script
   */
  async sendMessage(message) {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage(message, (response) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
        } else {
          resolve(response || {});
        }
      });
    });
  }
}

// Initialize popup when DOM is loaded
document.addEventListener("DOMContentLoaded", () => {
  new SemrushPopup();
});

// Handle any uncaught errors
window.addEventListener("error", (event) => {
  console.error("Popup error:", event.error);
});

// Handle unhandled promise rejections
window.addEventListener("unhandledrejection", (event) => {
  console.error("Popup promise rejection:", event.reason);
});
