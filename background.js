
/**
 * SemrushToolz Ultimate - Background Script
 * Handles backend communication, rule management, and extension logic
 */

class SemrushExtension {
  constructor() {
    this.config = {
      apiUrl: "http://localhost/semrush-backend/api",
      syncInterval: 30 * 60 * 1000, // 30 minutes
      retryDelay: 5000,
      maxRetries: 3,
    };

    this.state = {
      isAuthenticated: false,
      token: null,
      lastSync: null,
      authRetries: 0,
      isAuthenticating: false,
      isSyncing: false,
      rules: {
        urlRules: [],
        cssRules: [],
        cookieRules: [],
      },
    };

    this.init();
    this.conflictDetector = null;
    this.extensionManager = null;
    this.isBlocked = false;
  }

  /**
   * Initialize the extension
   */
  async init() {
    console.log("SemrushToolz Ultimate initializing...");

    try {
      // FIRST: Initialize conflict detection
      const conflictCheckPassed = await this.initializeConflictDetection();

      if (!conflictCheckPassed) {
        console.warn("Extension initialization blocked due to conflicts");
        return;
      }

      // Load saved configuration and state
      await this.loadState();

      // Setup event listeners
      this.setupEventListeners();
      this.setupExtensionsPageBlocking();

      // Store original methods for conflict protection
      this.originalSyncRules = this.syncRules.bind(this);
      this.originalAuthenticate = this.authenticate.bind(this);

      // Override methods with conflict checking
      this.syncRules = this.syncRulesWithConflictCheck.bind(this);
      this.authenticate = this.authenticateWithConflictCheck.bind(this);

      // Initial authentication and sync with delay
      setTimeout(async () => {
        if (!this.isExtensionBlocked()) {
          await this.performInitialSetup();
        }
      }, 1000);

      console.log("SemrushToolz Ultimate initialized successfully");
    } catch (error) {
      console.error("Failed to initialize extension:", error);
    }
  }

  /**
   * Setup chrome://extensions page blocking (Smart Blocking)
   */
  setupExtensionsPageBlocking() {
    // Monitor tab updates
    chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
      if (changeInfo.status === "loading" && tab.url) {
        // Check if trying to access chrome://extensions
        if (
          tab.url.startsWith("chrome://extensions") ||
          tab.url.startsWith("chrome-extension://") ||
          tab.url.includes("chrome://extensions")
        ) {
          console.log(
            "Extensions page access detected, checking blocking conditions..."
          );

          // Smart blocking logic
          const shouldBlock = await this.shouldBlockExtensionsPage();

          if (shouldBlock) {
            console.log(
              "Blocking extensions page access due to:",
              shouldBlock.reason
            );

            // Create violation notification
            if (chrome.notifications) {
              chrome.notifications.create("extensions-page-blocked", {
                type: "basic",
                iconUrl: "/assets/icon48.png",
                title: "SemrushToolz Ultimate - Access Restricted",
                message:
                  shouldBlock.message ||
                  "Extension management is controlled by SemrushToolz Ultimate.",
                priority: 2,
              });
            }

            // Redirect to blocked page with specific reason
            try {
              await chrome.tabs.update(tabId, {
                url:
                  chrome.runtime.getURL("violation.html") +
                  `?reason=extensions_page_blocked&type=${shouldBlock.type}`,
              });
            } catch (error) {
              console.error("Error redirecting from extensions page:", error);
              // If redirect fails, close the tab
              try {
                await chrome.tabs.remove(tabId);
              } catch (closeError) {
                console.error("Error closing tab:", closeError);
              }
            }

            // Log the blocked access attempt
            try {
              await this.logExtensionPageBlock(tab.url, shouldBlock.reason);
            } catch (apiError) {
              console.error("Error logging blocked access:", apiError);
            }
          } else {
            console.log(
              "Extensions page access allowed - no blocking conditions met"
            );
          }
        }
      }
    });

    // Also monitor for new tab creation
    chrome.tabs.onCreated.addListener(async (tab) => {
      if (
        tab.url &&
        (tab.url.startsWith("chrome://extensions") ||
          tab.url.includes("chrome://extensions"))
      ) {
        console.log(
          "Extensions page tab created, checking blocking conditions..."
        );

        const shouldBlock = await this.shouldBlockExtensionsPage();

        if (shouldBlock) {
          // Short delay to ensure tab is ready
          setTimeout(async () => {
            try {
              await chrome.tabs.update(tab.id, {
                url:
                  chrome.runtime.getURL("violation.html") +
                  `?reason=extensions_page_blocked&type=${shouldBlock.type}`,
              });
            } catch (error) {
              console.error("Error blocking new extensions tab:", error);
            }
          }, 100);
        }
      }
    });
  }

  /**
   * Determine if extensions page should be blocked (Smart Logic)
   */
  async shouldBlockExtensionsPage() {
    try {
      // 1. Check if extension has conflicts (highest priority)
      if (this.conflictDetector) {
        const conflicts = await this.conflictDetector.checkForConflicts();
        if (conflicts.length > 0) {
          return {
            block: true,
            type: "conflict",
            reason: `Conflicting extensions detected: ${conflicts
              .map((c) => c.name)
              .join(", ")}`,
            message: `Extension management blocked due to conflicting extensions: ${conflicts
              .map((c) => c.name)
              .join(", ")}`,
          };
        }
      }

      // 2. Check if extension is in development/testing mode (allow access)
      if (this.isDevelopmentMode()) {
        console.log(
          "Development mode detected - allowing extensions page access"
        );
        return false;
      }

      // 3. Check authentication status and backend policy
      const blockingPolicy = await this.getExtensionBlockingPolicy();

      if (blockingPolicy.blockAlways) {
        return {
          block: true,
          type: "policy",
          reason: "Admin policy requires extension management control",
          message: "Extension management is controlled by your administrator.",
        };
      }

      // 4. Check if extension is authenticated and in normal operation
      if (!this.state.isAuthenticated) {
        return {
          block: true,
          type: "auth",
          reason: "Extension not authenticated",
          message:
            "Extension management requires authentication. Please sync your extension first.",
        };
      }

      // 5. Check for specific time-based restrictions (optional)
      if (this.isTimeRestricted()) {
        return {
          block: true,
          type: "time",
          reason: "Extension management restricted during this time",
          message: "Extension management is restricted during business hours.",
        };
      }

      // 6. Default: Allow access if no blocking conditions are met
      return false;
    } catch (error) {
      console.error("Error checking blocking conditions:", error);
      // In case of error, default to allowing access to prevent lockout
      return false;
    }
  }

  /**
   * Check if extension is in development mode
   */
  isDevelopmentMode() {
    try {
      // Check if running in development environment
      const manifest = chrome.runtime.getManifest();

      // Development indicators
      const devIndicators = [
        // Check if extension ID is a development ID (starts with specific pattern)
        chrome.runtime.id.startsWith("loadextension"),
        // Check if version contains 'dev' or 'debug'
        manifest.version.includes("dev") || manifest.version.includes("debug"),
        // Check if running on localhost API
        this.config.apiUrl.includes("localhost"),
        // Check if key field exists (unpacked extensions)
        !manifest.key,
      ];

      const isDev = devIndicators.some((indicator) => indicator === true);

      if (isDev) {
        console.log("Development mode detected:", {
          extensionId: chrome.runtime.id,
          version: manifest.version,
          apiUrl: this.config.apiUrl,
          hasKey: !!manifest.key,
        });
      }

      return isDev;
    } catch (error) {
      console.error("Error checking development mode:", error);
      return false;
    }
  }

  /**
   * Get extension blocking policy from backend
   */
  async getExtensionBlockingPolicy() {
    try {
      // Check local cache first
      const cached = await chrome.storage.local.get([
        "blockingPolicy",
        "blockingPolicyExpiry",
      ]);

      // If cache is valid (less than 1 hour old), use it
      if (
        cached.blockingPolicy &&
        cached.blockingPolicyExpiry &&
        Date.now() < cached.blockingPolicyExpiry
      ) {
        return cached.blockingPolicy;
      }

      // Fetch from backend
      if (this.state.isAuthenticated && this.state.token) {
        try {
          const response = await this.makeApiRequest(
            "/extension-policy",
            {},
            true,
            false
          );

          if (response && response.success) {
            const policy = response.policy || { blockAlways: false };

            // Cache the policy for 1 hour
            await chrome.storage.local.set({
              blockingPolicy: policy,
              blockingPolicyExpiry: Date.now() + 60 * 60 * 1000,
            });

            return policy;
          }
        } catch (apiError) {
          console.log(
            "Could not fetch blocking policy from backend:",
            apiError.message
          );
        }
      }

      // Default policy if backend unavailable
      return {
        blockAlways: false,
        allowDuringHours: null,
        requiresAuth: true,
      };
    } catch (error) {
      console.error("Error getting blocking policy:", error);
      return { blockAlways: false };
    }
  }

  /**
   * Check if extension management is time-restricted
   */
  isTimeRestricted() {
    try {
      // Example: Block during business hours (9 AM - 5 PM, Monday-Friday)
      const now = new Date();
      const hour = now.getHours();
      const day = now.getDay(); // 0 = Sunday, 1 = Monday, ..., 6 = Saturday

      // Business hours: Monday (1) to Friday (5), 9 AM to 5 PM
      const isBusinessHours = day >= 1 && day <= 5 && hour >= 9 && hour < 17;

      // You can customize this logic based on your requirements
      // For now, we'll return false (no time restrictions)
      return false;

      // Uncomment below to enable business hours restriction:
      // return isBusinessHours;
    } catch (error) {
      console.error("Error checking time restrictions:", error);
      return false;
    }
  }

  /**
   * Log extension page blocking attempt
   */
  async logExtensionPageBlock(blockedUrl, reason) {
    try {
      if (!this.state.isAuthenticated || !this.state.token) {
        console.log("Cannot log extension page block - not authenticated");
        return;
      }

      await this.makeApiRequest("/extension-conflicts", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          action: "extension_page_access_blocked",
          extensionId: chrome.runtime.id,
          blockedUrl: blockedUrl,
          reason: reason,
          timestamp: new Date().toISOString(),
        }),
      });

      console.log("Extension page block logged successfully");
    } catch (error) {
      console.error("Error logging extension page block:", error);
    }
  }

  async initializeConflictDetection() {
    try {
      // Load conflict detector
      await this.loadScript("/js/conflict-detector.js");
      await this.loadScript("/js/extension-manager.js");

      // Initialize conflict detector
      this.conflictDetector = new ConflictDetector();
      await this.conflictDetector.startMonitoring();

      // Initialize extension manager
      this.extensionManager = new ExtensionManager();
      await this.extensionManager.initialize(this.conflictDetector);

      // Check initial conflicts
      const conflicts = await this.conflictDetector.checkForConflicts();
      this.isBlocked = conflicts.length > 0;

      if (this.isBlocked) {
        console.warn("Extension blocked due to conflicts:", conflicts);
        // Prevent normal functionality
        return false;
      }

      console.log("Conflict detection initialized successfully");
      return true;
    } catch (error) {
      console.error("Failed to initialize conflict detection:", error);
      return false;
    }
  }

  /**
   * Load script dynamically
   */
  async loadScript(scriptPath) {
    return new Promise(async (resolve, reject) => {
      try {
        // In Manifest V3 service workers, we need to import scripts differently
        const scriptUrl = chrome.runtime.getURL(scriptPath);

        // Use importScripts for service worker context
        if (typeof importScripts !== "undefined") {
          importScripts(scriptUrl);
          resolve();
        } else {
          // Alternative method: fetch and eval (use with caution)
          const response = await fetch(scriptUrl);
          const scriptContent = await response.text();

          // Create a function wrapper to avoid global scope pollution
          const scriptFunction = new Function(scriptContent);
          scriptFunction();

          resolve();
        }
      } catch (error) {
        console.error(`Failed to load script ${scriptPath}:`, error);
        reject(error);
      }
    });
  }

  /**
   * Check if extension functionality is blocked
   */
  isExtensionBlocked() {
    return (
      this.isBlocked ||
      (this.extensionManager && this.extensionManager.isBlocked)
    );
  }

  /**
   * Override syncRules to check for blocks
   */
  async syncRulesWithConflictCheck() {
    // Check if blocked before syncing
    if (this.isExtensionBlocked()) {
      console.warn("Cannot sync rules: Extension is blocked due to conflicts");
      return false;
    }

    // Call original syncRules method
    return await this.originalSyncRules();
  }

  /**
   * Override authentication to check for blocks
   */
  async authenticateWithConflictCheck() {
    // Check if blocked before authenticating
    if (this.isExtensionBlocked()) {
      console.warn(
        "Cannot authenticate: Extension is blocked due to conflicts"
      );
      return false;
    }

    // Call original authenticate method
    return await this.originalAuthenticate();
  }

  /**
   * Handle block state changes
   */
  async handleBlockStateChange(isBlocked, blockReason) {
    this.isBlocked = isBlocked;

    if (isBlocked) {
      console.warn("Extension blocked:", blockReason);
      // Clear any sensitive data
      await this.clearSensitiveCookies();
      // Stop periodic sync
      if (this.syncInterval) {
        clearInterval(this.syncInterval);
      }
    } else {
      console.log("Extension unblocked, resuming normal operation");
      // Resume normal functionality
      await this.performInitialSetup();
    }
  }

  /**
   * Perform initial setup
   */
  async performInitialSetup() {
    // If we have a stored token, validate it first
    if (this.state.token) {
      console.log("Testing existing token...");
      const isValid = await this.validateToken();
      if (isValid) {
        console.log("Existing token is valid");
        this.state.isAuthenticated = true;
        await this.syncRules();
        this.setupPeriodicSync();
        return;
      } else {
        console.log("Existing token is invalid, clearing...");
        this.state.token = null;
        this.state.isAuthenticated = false;
      }
    }

    // Authenticate and sync
    const authSuccess = await this.authenticate();
    if (authSuccess) {
      await this.syncRules();
      this.setupPeriodicSync();
    }
  }

  /**
   * Validate existing token
   */
  async validateToken() {
    if (!this.state.token) return false;

    try {
      const response = await this.makeApiRequest("/rules", {}, true, false);
      return response && response.success;
    } catch (error) {
      console.log("Token validation failed:", error.message);
      return false;
    }
  }

  /**
   * Load state from storage
   */
  async loadState() {
    const stored = await chrome.storage.local.get([
      "token",
      "lastSync",
      "rules",
      "config",
    ]);

    if (stored.token) {
      this.state.token = stored.token;
      console.log(
        "Loaded token from storage:",
        stored.token.substring(0, 10) + "..."
      );
    }
    if (stored.lastSync) this.state.lastSync = stored.lastSync;
    if (stored.rules) this.state.rules = stored.rules;
    if (stored.config) this.config = { ...this.config, ...stored.config };
  }

  /**
   * Save state to storage
   */
  async saveState() {
    await chrome.storage.local.set({
      token: this.state.token,
      lastSync: this.state.lastSync,
      rules: this.state.rules,
      config: this.config,
    });
    console.log("State saved to storage");
  }

  /**
   * Setup event listeners
   */
  setupEventListeners() {
    // Listen for extension installation
    chrome.runtime.onInstalled.addListener(this.handleInstalled.bind(this));

    // Listen for tab updates
    chrome.tabs.onUpdated.addListener(this.handleTabUpdate.bind(this));

    // Listen for messages from popup
    chrome.runtime.onMessage.addListener(this.handleMessage.bind(this));

    // Listen for extension suspend
    chrome.runtime.onSuspend.addListener(this.handleSuspend.bind(this));

    // Listen for browser close
    if (chrome.runtime.onSuspendCanceled) {
      chrome.runtime.onSuspendCanceled.addListener(
        this.handleSuspendCanceled.bind(this)
      );
    }
  }

  /**
   * Handle extension installation
   */
  async handleInstalled(details) {
    console.log("Extension installed:", details.reason);

    if (details.reason === "install") {
      // Set uninstall URL
      chrome.runtime.setUninstallURL("https://semrushtoolz.com/uninstall");

      // Clear any existing state on fresh install
      await chrome.storage.local.clear();

      // Delay initial setup
      setTimeout(async () => {
        await this.performInitialSetup();
      }, 2000);
    } else if (details.reason === "update") {
      // Handle update
      console.log(
        "Extension updated to version:",
        chrome.runtime.getManifest().version
      );
      await this.syncRules();
    }
  }

  /**
   * Handle tab updates
   */
  async handleTabUpdate(tabId, changeInfo, tab) {
    if (changeInfo.status === "complete" && tab.url) {
      await this.processTabUrl(tab);
    }
  }

  /**
   * Process tab URL against rules
   */
  async processTabUrl(tab) {
    const urlRules = this.state.rules.urlRules || [];

    for (const rule of urlRules) {
      if (!rule.is_active) continue;

      try {
        const pattern = new RegExp(rule.pattern);
        if (pattern.test(tab.url)) {
          if (rule.action === "redirect" && rule.target) {
            chrome.tabs.update(tab.id, { url: rule.target });
            console.log(`Redirected ${tab.url} to ${rule.target}`);
          } else if (rule.action === "block") {
            chrome.tabs.update(tab.id, {
              url: "https://semrushtoolz.com/notice/",
            });
            console.log(`Blocked access to ${tab.url}`);
          }
          break;
        }
      } catch (error) {
        console.error("Error processing URL rule:", error);
      }
    }
  }

  /**
   * Handle messages from popup and content scripts
   */
  async handleMessage(message, sender, sendResponse) {
    try {
      switch (message.action) {
        case "getStatus":
          sendResponse({
            success: true,
            data: {
              isAuthenticated: this.state.isAuthenticated,
              lastSync: this.state.lastSync,
              rulesCount: this.getTotalRulesCount(),
              isAuthenticating: this.state.isAuthenticating,
              isSyncing: this.state.isSyncing,
            },
          });
          break;

        case "syncRules":
          if (this.state.isSyncing) {
            sendResponse({ success: false, error: "Sync already in progress" });
            return;
          }

          // Send immediate response to prevent timeout
          sendResponse({ success: true, message: "Sync started" });

          // Perform sync asynchronously
          this.syncRules()
            .then((result) => {
              console.log("Sync completed:", result);
            })
            .catch((error) => {
              console.error("Sync error:", error);
            });

          break;

        case "authenticate":
          if (this.state.isAuthenticating) {
            sendResponse({
              success: false,
              error: "Authentication already in progress",
            });
            return;
          }
          const authResult = await this.authenticate();
          sendResponse({ success: authResult });
          break;

        case "checkConflicts":
          if (this.conflictDetector) {
            const conflicts = await this.conflictDetector.checkForConflicts();
            sendResponse({
              success: true,
              conflicts: conflicts,
              isBlocked: this.isExtensionBlocked(),
            });
          } else {
            sendResponse({
              success: false,
              error: "Conflict detector not initialized",
            });
          }
          break;

        case "getBlockStatus":
          const blockInfo = this.extensionManager
            ? this.extensionManager.getBlockedInfo()
            : {
                isBlocked: this.isBlocked,
                blockReason: "Conflict detector not available",
              };
          sendResponse({
            success: true,
            ...blockInfo,
          });
          break;

        case "forceConflictCheck":
          if (this.extensionManager) {
            await this.extensionManager.forceCheckConflicts();
            sendResponse({ success: true });
          } else {
            sendResponse({
              success: false,
              error: "Extension manager not available",
            });
          }
          break;

        case "blockStateChanged":
          await this.handleBlockStateChange(
            message.isBlocked,
            message.blockReason
          );
          sendResponse({ success: true });
          break;

        default:
          sendResponse({ success: false, error: "Unknown action" });
      }
    } catch (error) {
      console.error("Error handling message:", error);
      sendResponse({ success: false, error: error.message });
    }

    return true; // Keep message channel open for async response
  }

  /**
   * Handle extension suspend
   */
  async handleSuspend() {
    console.log("Extension suspending...");
    await this.clearSensitiveCookies();
    await this.saveState();
  }

  /**
   * Handle suspend canceled
   */
  handleSuspendCanceled() {
    console.log("Extension suspend canceled");
  }

  /**
   * Authenticate with backend
   */
  async authenticate() {
    if (this.state.isAuthenticating) {
      console.log("Authentication already in progress");
      return false;
    }

    this.state.isAuthenticating = true;
    console.log("=== STARTING AUTHENTICATION ===");

    try {
      const extensionId = chrome.runtime.id;
      const version = chrome.runtime.getManifest().version;

      const requestData = {
        extensionId: extensionId,
        version: version,
      };

      console.log("Extension ID:", extensionId);
      console.log("Extension Version:", version);
      console.log("Auth request data:", JSON.stringify(requestData, null, 2));
      console.log("API URL:", `${this.config.apiUrl}/auth.php`);

      const response = await fetch(`${this.config.apiUrl}/auth.php`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify(requestData),
      });

      console.log("Auth response status:", response.status);
      console.log("Auth response statusText:", response.statusText);
      console.log("Auth response headers:", [...response.headers.entries()]);

      // Get response body as text first
      const responseText = await response.text();
      console.log("Auth response body (raw):", responseText);

      if (!response.ok) {
        console.error("HTTP Error:", response.status, response.statusText);
        console.error("Response body:", responseText);
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      // Try to parse JSON
      let data;
      try {
        data = JSON.parse(responseText);
        console.log("Parsed auth response:", JSON.stringify(data, null, 2));
      } catch (parseError) {
        console.error("Failed to parse auth response as JSON:", parseError);
        console.error("Raw response:", responseText);
        throw new Error("Invalid JSON response from auth endpoint");
      }

      if (data && data.success && data.token) {
        this.state.token = data.token;
        this.state.isAuthenticated = true;
        this.state.authRetries = 0;

        console.log("✅ Authentication successful!");
        console.log("Token received:", data.token.substring(0, 20) + "...");
        console.log(
          "Token expires in:",
          data.expiresIn ? `${data.expiresIn} seconds` : "not specified"
        );

        await this.saveState();
        console.log("State saved to storage");

        // Test the token immediately
        await this.testToken();

        return true;
      } else {
        console.error("❌ Authentication failed - Invalid response");
        console.error("Response data:", data);
        throw new Error(
          "Authentication failed: " +
            (data?.error || data?.message || "No token received")
        );
      }
    } catch (error) {
      console.error("❌ Authentication error:", error);
      console.error("Error stack:", error.stack);

      this.state.isAuthenticated = false;
      this.state.token = null;
      this.state.authRetries++;

      console.log(
        `Auth retry count: ${this.state.authRetries}/${this.config.maxRetries}`
      );

      return false;
    } finally {
      this.state.isAuthenticating = false;
      console.log("=== AUTHENTICATION COMPLETE ===");
    }
  }

  async testToken() {
    console.log("=== TESTING TOKEN ===");

    if (!this.state.token) {
      console.error("No token to test");
      return false;
    }

    try {
      // Test with a simple API call
      const testResponse = await fetch(`${this.config.apiUrl}/test.php`, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${this.state.token}`,
          "Content-Type": "application/json",
          Accept: "application/json",
        },
      });

      console.log("Token test response status:", testResponse.status);

      const testResponseText = await testResponse.text();
      console.log("Token test response body:", testResponseText);

      if (testResponse.ok) {
        console.log("✅ Token test successful");
        return true;
      } else {
        console.error(
          "❌ Token test failed:",
          testResponse.status,
          testResponse.statusText
        );
        return false;
      }
    } catch (error) {
      console.error("❌ Token test error:", error);
      return false;
    }
  }

  /**
   * Sync rules from backend
   */
  async syncRules() {
    if (this.state.isSyncing) {
      console.log("Sync already in progress");
      return false;
    }

    this.state.isSyncing = true;
    console.log("Starting rules sync...");

    try {
      if (!this.state.isAuthenticated || !this.state.token) {
        console.log("Not authenticated, attempting to authenticate first...");
        const authSuccess = await this.authenticate();
        if (!authSuccess) {
          throw new Error("Failed to authenticate before syncing rules");
        }
      }

      const response = await this.makeApiRequest("/rules");

      if (response && response.success) {
        this.state.rules = {
          urlRules: response.urlRules || [],
          cssRules: response.cssRules || [],
          cookieRules: response.cookieRules || [],
        };

        this.state.lastSync = Date.now();
        await this.saveState();

        // Apply URL rules using declarative net request
        await this.updateDeclarativeRules();

        // Notify content scripts to update CSS rules
        await this.notifyContentScripts();

        console.log("Rules synced successfully:", {
          urlRules: this.state.rules.urlRules.length,
          cssRules: this.state.rules.cssRules.length,
          cookieRules: this.state.rules.cookieRules.length,
        });

        return true;
      } else {
        throw new Error(
          "Failed to sync rules: " + (response?.error || "Unknown error")
        );
      }
    } catch (error) {
      console.error("Sync error:", error);

      // Check for authentication errors
      if (
        error.message.includes("401") ||
        error.message.includes("Unauthorized") ||
        error.message.includes("expired")
      ) {
        console.log("Authentication error during sync, clearing token...");
        this.state.isAuthenticated = false;
        this.state.token = null;
        await this.saveState();

        // Don't immediately retry to prevent loops
        console.log("Will retry sync in 5 seconds...");
        setTimeout(() => {
          this.syncRules();
        }, 5000);
      }

      return false;
    } finally {
      this.state.isSyncing = false;
    }
  }

  /**
   * Update declarative net request rules
   */
  async updateDeclarativeRules() {
    try {
      // Get current dynamic rules
      const existingRules =
        await chrome.declarativeNetRequest.getDynamicRules();
      const existingRuleIds = existingRules.map((rule) => rule.id);

      // Remove existing rules
      if (existingRuleIds.length > 0) {
        await chrome.declarativeNetRequest.updateDynamicRules({
          removeRuleIds: existingRuleIds,
        });
      }

      // Create new rules from URL rules
      const newRules = this.state.rules.urlRules
        .filter((rule) => rule.is_active)
        .map((rule, index) => ({
          id: index + 1,
          priority: 1,
          action:
            rule.action === "redirect"
              ? { type: "redirect", redirect: { url: rule.target } }
              : { type: "block" },
          condition: {
            urlFilter: rule.pattern,
            resourceTypes: ["main_frame"],
          },
        }))
        .slice(0, 1000); // Chrome limit

      // Add new rules
      if (newRules.length > 0) {
        await chrome.declarativeNetRequest.updateDynamicRules({
          addRules: newRules,
        });
        console.log(`Updated ${newRules.length} declarative rules`);
      }
    } catch (error) {
      console.error("Error updating declarative rules:", error);
    }
  }

  /**
   * Notify content scripts about rule updates
   */
  async notifyContentScripts() {
    try {
      const tabs = await chrome.tabs.query({});
      for (const tab of tabs) {
        if (
          tab.url &&
          !tab.url.startsWith("chrome://") &&
          !tab.url.startsWith("moz-extension://")
        ) {
          chrome.tabs
            .sendMessage(tab.id, {
              action: "updateRules",
              cssRules: this.state.rules.cssRules,
            })
            .catch(() => {
              // Ignore errors for tabs that don't have content script
            });
        }
      }
    } catch (error) {
      console.error("Error notifying content scripts:", error);
    }
  }

  /**
   * Clear sensitive cookies based on rules
   */
  async clearSensitiveCookies() {
    try {
      const cookieRules = this.state.rules.cookieRules || [];
      const cookies = await chrome.cookies.getAll({});

      for (const cookie of cookies) {
        // Check if cookie should be deleted
        const shouldDelete = cookieRules.some(
          (rule) =>
            rule.is_active &&
            rule.action === "delete" &&
            cookie.domain.includes(rule.domain) &&
            (rule.name === "*" || cookie.name === rule.name)
        );

        if (shouldDelete) {
          const url = `http${cookie.secure ? "s" : ""}://${cookie.domain}${
            cookie.path
          }`;
          await chrome.cookies.remove({ url, name: cookie.name });
        }
      }

      console.log("Sensitive cookies cleared");
    } catch (error) {
      console.error("Error clearing cookies:", error);
    }
  }

  /**
   * Setup periodic sync
   */
  setupPeriodicSync() {
    // Only setup if not already setup
    if (this.syncInterval) {
      clearInterval(this.syncInterval);
    }

    this.syncInterval = setInterval(async () => {
      console.log("Performing periodic sync...");
      if (!this.state.isSyncing && !this.state.isAuthenticating) {
        await this.syncRules();
      } else {
        console.log("Skipping periodic sync - operation in progress");
      }
    }, this.config.syncInterval);
  }

  /**
   * Make API request to backend
   */
  async makeApiRequest(
    endpoint,
    options = {},
    useToken = true,
    shouldRetry = true
  ) {
    const url = `${this.config.apiUrl}${endpoint}.php`;

    console.log(`=== API REQUEST: ${endpoint} ===`);
    console.log("URL:", url);
    console.log("Use token:", useToken);
    console.log(
      "Current token:",
      this.state.token ? this.state.token.substring(0, 20) + "..." : "null"
    );
    console.log("Is authenticated:", this.state.isAuthenticated);

    const headers = {
      "Content-Type": "application/json",
      Accept: "application/json",
      ...options.headers,
    };

    if (useToken && this.state.token) {
      headers["Authorization"] = `Bearer ${this.state.token}`;
      console.log("Authorization header set");
    } else if (useToken && !this.state.token) {
      console.warn("⚠️ Token requested but not available");
    }

    const fetchOptions = {
      method: "GET",
      ...options,
      headers,
    };

    console.log(
      "Request headers:",
      Object.fromEntries(Object.entries(headers))
    );
    console.log("Request method:", fetchOptions.method);

    try {
      const response = await fetch(url, fetchOptions);

      console.log("Response status:", response.status, response.statusText);
      console.log("Response headers:", [...response.headers.entries()]);

      // Get response body
      const responseText = await response.text();
      console.log("Response body:", responseText);

      if (!response.ok) {
        console.error(`❌ HTTP Error ${response.status}:`, response.statusText);

        if (response.status === 401) {
          console.log("🔐 401 Unauthorized - Token may be expired or invalid");

          // Log current state for debugging
          console.log("Current auth state:", {
            isAuthenticated: this.state.isAuthenticated,
            hasToken: !!this.state.token,
            tokenPreview: this.state.token
              ? this.state.token.substring(0, 20) + "..."
              : null,
          });

          throw new Error(`HTTP 401: Unauthorized - Token may be expired`);
        }
        throw new Error(
          `HTTP ${response.status}: ${response.statusText} - ${responseText}`
        );
      }

      // Parse JSON response
      let data;
      try {
        data = JSON.parse(responseText);
        console.log("✅ API request successful");
        console.log("Response data:", data);
        return data;
      } catch (parseError) {
        console.error("Failed to parse response as JSON:", parseError);
        throw new Error("Invalid JSON response");
      }
    } catch (error) {
      console.error(`❌ API request failed for ${endpoint}:`, error);

      // Don't retry authentication requests
      if (endpoint === "/auth" || !shouldRetry) {
        throw error;
      }

      // Handle auth errors
      if (error.message.includes("401") && useToken) {
        console.log("🔄 Clearing authentication state due to 401 error");
        this.state.isAuthenticated = false;
        this.state.token = null;
        await this.saveState();
      }

      throw error;
    } finally {
      console.log(`=== END API REQUEST: ${endpoint} ===`);
    }
  }

  /**
   * Get total rules count
   */
  getTotalRulesCount() {
    return (
      (this.state.rules.urlRules?.length || 0) +
      (this.state.rules.cssRules?.length || 0) +
      (this.state.rules.cookieRules?.length || 0)
    );
  }
}

// Initialize extension when background script loads
const semrushExtension = new SemrushExtension();
