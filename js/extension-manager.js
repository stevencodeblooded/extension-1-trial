/**
 * SemrushToolz Ultimate - Extension Manager
 * Manages extension state and prevents functionality when blocked
 */

class ExtensionManager {
  constructor() {
    this.isBlocked = false;
    this.blockReason = "";
    this.conflictDetector = null;
    this.originalFunctions = new Map();
  }

  /**
   * Initialize extension manager
   */
  async initialize(conflictDetector) {
    this.conflictDetector = conflictDetector;

    // Check if extension is blocked
    await this.checkBlockedState();

    // Setup function interceptors if blocked
    if (this.isBlocked) {
      this.interceptExtensionFunctions();
    }

    // Monitor blocked state changes
    this.setupBlockedStateMonitor();
  }

  /**
   * Check if extension is currently blocked
   */
  async checkBlockedState() {
    try {
      // Check from conflict detector
      if (this.conflictDetector) {
        const conflicts = await this.conflictDetector.checkForConflicts();
        this.isBlocked = conflicts.length > 0;

        if (this.isBlocked) {
          this.blockReason = `Conflicting extensions detected: ${conflicts
            .map((c) => c.name)
            .join(", ")}`;
        } else {
          this.blockReason = "";
        }
      }

      // Store blocked state
      await chrome.storage.local.set({
        isBlocked: this.isBlocked,
        blockReason: this.blockReason,
        lastCheck: Date.now(),
      });

      console.log("Extension blocked state:", this.isBlocked, this.blockReason);
    } catch (error) {
      console.error("Error checking blocked state:", error);
    }
  }

  /**
   * Intercept extension functions when blocked
   */
  interceptExtensionFunctions() {
    // Intercept chrome.tabs API
    if (chrome.tabs && chrome.tabs.update) {
      this.originalFunctions.set("tabs.update", chrome.tabs.update);
      chrome.tabs.update = this.createBlockedFunction("tabs.update");
    }

    // Intercept chrome.cookies API
    if (chrome.cookies && chrome.cookies.remove) {
      this.originalFunctions.set("cookies.remove", chrome.cookies.remove);
      chrome.cookies.remove = this.createBlockedFunction("cookies.remove");
    }

    // Intercept declarativeNetRequest API
    if (
      chrome.declarativeNetRequest &&
      chrome.declarativeNetRequest.updateDynamicRules
    ) {
      this.originalFunctions.set(
        "declarativeNetRequest.updateDynamicRules",
        chrome.declarativeNetRequest.updateDynamicRules
      );
      chrome.declarativeNetRequest.updateDynamicRules =
        this.createBlockedFunction("declarativeNetRequest.updateDynamicRules");
    }

    // Intercept storage API (partial)
    if (chrome.storage && chrome.storage.local && chrome.storage.local.set) {
      const originalSet = chrome.storage.local.set;
      this.originalFunctions.set("storage.local.set", originalSet);

      chrome.storage.local.set = (items, callback) => {
        // Allow only blocked state and essential data
        const allowedKeys = ["isBlocked", "blockReason", "lastCheck", "token"];
        const filteredItems = {};

        for (const [key, value] of Object.entries(items)) {
          if (allowedKeys.includes(key)) {
            filteredItems[key] = value;
          }
        }

        if (Object.keys(filteredItems).length > 0) {
          originalSet(filteredItems, callback);
        } else if (callback) {
          callback();
        }
      };
    }

    console.log("Extension functions intercepted due to blocking");
  }

  /**
   * Create a blocked function that shows violation message
   */
  createBlockedFunction(functionName) {
    return (...args) => {
      console.warn(
        `Function ${functionName} blocked due to: ${this.blockReason}`
      );

      // Show violation message
      this.showBlockedMessage();

      // Return a rejected promise or false
      const callback = args[args.length - 1];
      if (typeof callback === "function") {
        callback(
          new Error(`Extension functionality blocked: ${this.blockReason}`)
        );
      }

      return Promise.reject(
        new Error(`Extension functionality blocked: ${this.blockReason}`)
      );
    };
  }

  /**
   * Restore original functions when unblocked
   */
  restoreOriginalFunctions() {
    for (const [path, originalFunction] of this.originalFunctions) {
      const pathParts = path.split(".");
      let obj = chrome;

      // Navigate to the object
      for (let i = 0; i < pathParts.length - 1; i++) {
        obj = obj[pathParts[i]];
      }

      // Restore original function
      const functionName = pathParts[pathParts.length - 1];
      obj[functionName] = originalFunction;
    }

    this.originalFunctions.clear();
    console.log("Original extension functions restored");
  }

  /**
   * Show blocked message to user
   */
  showBlockedMessage() {
    // Create notification if possible
    if (chrome.notifications) {
      chrome.notifications.create("blocked-attempt", {
        type: "basic",
        iconUrl: "/assets/icon48.png",
        title: "SemrushToolz Ultimate - Blocked",
        message: `Extension functionality blocked. ${this.blockReason}`,
        priority: 1,
      });
    }

    // Log for debugging
    console.warn("Extension functionality blocked:", this.blockReason);
  }

  /**
   * Setup monitor for blocked state changes
   */
  setupBlockedStateMonitor() {
    // Check blocked state every 10 seconds
    setInterval(async () => {
      const wasBlocked = this.isBlocked;
      await this.checkBlockedState();

      // If state changed
      if (wasBlocked !== this.isBlocked) {
        if (this.isBlocked) {
          // Just got blocked
          this.interceptExtensionFunctions();
          console.log("Extension blocked, functions intercepted");
        } else {
          // Just got unblocked
          this.restoreOriginalFunctions();
          console.log("Extension unblocked, functions restored");
        }

        // Notify background script of state change
        if (chrome.runtime && chrome.runtime.sendMessage) {
          chrome.runtime
            .sendMessage({
              action: "blockStateChanged",
              isBlocked: this.isBlocked,
              blockReason: this.blockReason,
            })
            .catch(() => {
              // Ignore errors if no listeners
            });
        }
      }
    }, 10000);
  }

  /**
   * Check if specific function should be blocked
   */
  isFunctionBlocked(functionName) {
    return this.isBlocked;
  }

  /**
   * Get blocked state info
   */
  getBlockedInfo() {
    return {
      isBlocked: this.isBlocked,
      blockReason: this.blockReason,
      conflictCount: this.conflictDetector
        ? this.conflictDetector.conflictingExtensions.size
        : 0,
    };
  }

  /**
   * Force check and handle conflicts
   */
  async forceCheckConflicts() {
    if (this.conflictDetector) {
      const conflicts = await this.conflictDetector.checkForConflicts();
      await this.conflictDetector.handleConflicts(conflicts);
      await this.checkBlockedState();
    }
  }

  /**
   * Manually unblock extension (for testing/debugging)
   */
  async manuallyUnblock() {
    console.warn("Manually unblocking extension (DEBUG ONLY)");
    this.isBlocked = false;
    this.blockReason = "";
    this.restoreOriginalFunctions();

    await chrome.storage.local.set({
      isBlocked: false,
      blockReason: "",
      lastCheck: Date.now(),
    });
  }
}

// Export for use in background script
if (typeof module !== "undefined" && module.exports) {
  module.exports = ExtensionManager;
} else if (typeof window !== "undefined") {
  window.ExtensionManager = ExtensionManager;
}
