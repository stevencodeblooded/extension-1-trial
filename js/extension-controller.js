/**
 * SemrushToolz Ultimate - Extension Controller
 * Manages all browser extensions on behalf of the backend
 */

class ExtensionController {
  constructor() {
    this.userExtensionId = null;
    this.managedExtensions = new Map();
    this.whitelistedExtensions = new Set();
    this.isInitialized = false;
    this.monitoringInterval = null;

    // Extensions that should never be disabled
    this.systemExtensions = new Set([
      chrome.runtime.id, // Our own extension
      "chrome://",
      "moz-extension://",
    ]);
  }

  /**
   * Initialize extension controller
   */
  async initialize(userExtensionId) {
    try {
      this.userExtensionId = userExtensionId;

      // Discover all installed extensions
      await this.discoverExtensions();

      // Register with backend
      await this.registerExtensionsWithBackend();

      // Apply control policies
      await this.applyControlPolicies();

      // Start monitoring
      this.startMonitoring();

      this.isInitialized = true;
      console.log("Extension controller initialized successfully");
      return true;
    } catch (error) {
      console.error("Failed to initialize extension controller:", error);
      return false;
    }
  }

  /**
   * Discover all installed extensions
   */
  async discoverExtensions() {
    try {
      const extensions = await chrome.management.getAll();
      this.managedExtensions.clear();

      for (const extension of extensions) {
        if (
          extension.type === "extension" &&
          !this.isSystemExtension(extension.id)
        ) {
          this.managedExtensions.set(extension.id, {
            id: extension.id,
            name: extension.name,
            version: extension.version,
            description: extension.description,
            enabled: extension.enabled,
            installType: extension.installType,
            type: extension.type,
            discoveredAt: Date.now(),
          });
        }
      }

      console.log(`Discovered ${this.managedExtensions.size} extensions`);
    } catch (error) {
      console.error("Error discovering extensions:", error);
    }
  }

  /**
   * Register extensions with backend
   */
  async registerExtensionsWithBackend() {
    try {
      const extensionsArray = Array.from(this.managedExtensions.values());

      const response = await this.makeApiRequest("/extension-management", {
        method: "POST",
        body: JSON.stringify({
          action: "register",
          extensions: extensionsArray,
        }),
      });

      if (response && response.success) {
        console.log(
          `Registered ${response.registered}/${response.total} extensions with backend`
        );
        return true;
      } else {
        throw new Error("Failed to register extensions with backend");
      }
    } catch (error) {
      console.error("Error registering extensions with backend:", error);
      return false;
    }
  }

  /**
   * Apply control policies (disable non-whitelisted extensions)
   */
  async applyControlPolicies() {
    try {
      // Get extensions requiring control from backend
      const response = await this.makeApiRequest(
        "/extension-management?action=requiring_control"
      );

      if (!response || !response.success) {
        console.warn("Could not get control policies from backend");
        return;
      }

      const extensionsToControl = response.extensions;

      for (const extension of extensionsToControl) {
        try {
          // Disable extension if it's currently enabled
          if (extension.is_enabled) {
            await chrome.management.setEnabled(extension.extension_id, false);
            console.log(`Disabled extension: ${extension.extension_name}`);

            // Log the action
            await this.logExtensionAction(
              extension.extension_id,
              "disable",
              "success"
            );
          }
        } catch (error) {
          console.error(
            `Failed to disable extension ${extension.extension_name}:`,
            error
          );
          await this.logExtensionAction(
            extension.extension_id,
            "disable",
            "error",
            { error: error.message }
          );
        }
      }
    } catch (error) {
      console.error("Error applying control policies:", error);
    }
  }

  /**
   * Start monitoring extension state changes
   */
  startMonitoring() {
    // Monitor extension installations
    if (chrome.management && chrome.management.onInstalled) {
      chrome.management.onInstalled.addListener(async (info) => {
        console.log("New extension installed:", info.name);

        if (!this.isSystemExtension(info.id)) {
          // Register new extension
          await this.registerSingleExtension(info);

          // Apply control policy (likely disable it)
          await this.applyControlPolicies();
        }
      });
    }

    // Monitor extension uninstalls
    if (chrome.management && chrome.management.onUninstalled) {
      chrome.management.onUninstalled.addListener((extensionId) => {
        console.log("Extension uninstalled:", extensionId);
        this.managedExtensions.delete(extensionId);
        this.logExtensionAction(extensionId, "uninstall", "success");
      });
    }

    // Monitor extension enable/disable attempts
    if (chrome.management && chrome.management.onEnabled) {
      chrome.management.onEnabled.addListener(async (info) => {
        console.log("Extension enabled:", info.name);

        if (!this.isSystemExtension(info.id)) {
          // Check if this extension should be backend controlled
          const shouldBeControlled = await this.shouldExtensionBeControlled(
            info.id
          );

          if (shouldBeControlled) {
            console.log(
              `Extension ${info.name} was enabled manually but should be backend controlled. Disabling...`
            );

            // Wait a moment then disable it again
            setTimeout(async () => {
              try {
                await chrome.management.setEnabled(info.id, false);
                await this.logExtensionAction(
                  info.id,
                  "auto_disable",
                  "success",
                  {
                    reason: "backend_controlled",
                    manual_attempt: true,
                  }
                );

                // Show notification to user
                this.showControlViolationNotification(info.name);
              } catch (error) {
                console.error(
                  `Failed to re-disable extension ${info.name}:`,
                  error
                );
              }
            }, 1000);
          }
        }
      });
    }

    // Periodic sync with backend
    this.monitoringInterval = setInterval(async () => {
      await this.syncWithBackend();
    }, 30000); // Every 30 seconds
  }

  /**
   * Register single extension with backend
   */
  async registerSingleExtension(extensionInfo) {
    try {
      const response = await this.makeApiRequest("/extension-management", {
        method: "POST",
        body: JSON.stringify({
          action: "register",
          extensions: [extensionInfo],
        }),
      });

      return response && response.success;
    } catch (error) {
      console.error("Error registering single extension:", error);
      return false;
    }
  }

  /**
   * Check if extension should be backend controlled
   */
  async shouldExtensionBeControlled(extensionId) {
    try {
      const response = await this.makeApiRequest(
        `/extension-management?action=list`
      );

      if (response && response.success) {
        const extension = response.extensions.find(
          (ext) => ext.extension_id === extensionId
        );
        return extension ? extension.backend_controlled : true; // Default to controlled
      }

      return true; // Default to controlled if can't determine
    } catch (error) {
      console.error("Error checking if extension should be controlled:", error);
      return true;
    }
  }

  /**
   * Sync with backend (get status updates)
   */
  async syncWithBackend() {
    try {
      const response = await this.makeApiRequest(
        "/extension-management?action=list"
      );

      if (response && response.success) {
        // Apply any status changes from backend
        for (const backendExt of response.extensions) {
          try {
            const currentState = await chrome.management.get(
              backendExt.extension_id
            );

            // If backend state differs from current state
            if (currentState.enabled !== backendExt.is_enabled) {
              await chrome.management.setEnabled(
                backendExt.extension_id,
                backendExt.is_enabled
              );
              console.log(
                `Updated ${backendExt.extension_name} to ${
                  backendExt.is_enabled ? "enabled" : "disabled"
                }`
              );

              await this.logExtensionAction(
                backendExt.extension_id,
                backendExt.is_enabled ? "enable" : "disable",
                "success",
                { source: "backend_sync" }
              );
            }
          } catch (error) {
            // Extension might be uninstalled
            console.log(
              `Extension ${backendExt.extension_name} not found locally`
            );
          }
        }
      }
    } catch (error) {
      console.error("Error syncing with backend:", error);
    }
  }

  /**
   * Show notification when user tries to manually enable controlled extension
   */
  showControlViolationNotification(extensionName) {
    if (chrome.notifications) {
      chrome.notifications.create("extension-control-violation", {
        type: "basic",
        iconUrl: "/assets/icon48.png",
        title: "SemrushToolz Ultimate - Extension Control",
        message: `Extension "${extensionName}" is managed by your administrator. Please use the admin panel to enable extensions.`,
        priority: 1,
      });
    }
  }

  /**
   * Check if extension is a system extension that shouldn't be managed
   */
  isSystemExtension(extensionId) {
    return (
      this.systemExtensions.has(extensionId) ||
      extensionId.startsWith("chrome://") ||
      extensionId.startsWith("moz-extension://")
    );
  }

  /**
   * Log extension action
   */
  async logExtensionAction(extensionId, action, status, details = {}) {
    try {
      await this.makeApiRequest("/extension-management", {
        method: "POST",
        body: JSON.stringify({
          action: "control_action",
          extension_id: extensionId,
          action_type: action,
          status: status,
          details: details,
        }),
      });
    } catch (error) {
      console.error("Error logging extension action:", error);
    }
  }

  /**
   * Make API request to backend
   */
  async makeApiRequest(endpoint, options = {}) {
    try {
      // Get token from storage
      const result = await chrome.storage.local.get(["token"]);
      const token = result.token;

      if (!token) {
        throw new Error("No authentication token available");
      }

      const url = `http://localhost/semrush-backend/api${endpoint}.php`;
      const response = await fetch(url, {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        ...options,
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error("API request failed:", error);
      throw error;
    }
  }

  /**
   * Get extension statistics
   */
  async getStatistics() {
    try {
      const response = await this.makeApiRequest(
        "/extension-management?action=stats"
      );
      return response && response.success ? response.stats : null;
    } catch (error) {
      console.error("Error getting extension statistics:", error);
      return null;
    }
  }

  /**
   * Stop monitoring and cleanup
   */
  cleanup() {
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
      this.monitoringInterval = null;
    }

    this.isInitialized = false;
    console.log("Extension controller cleaned up");
  }
}

// Export for use in background script
if (typeof module !== "undefined" && module.exports) {
  module.exports = ExtensionController;
} else if (typeof window !== "undefined") {
  window.ExtensionController = ExtensionController;
}
