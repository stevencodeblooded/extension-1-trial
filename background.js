/**
 * SemrushToolz Ultimate - Background Script
 * Handles backend communication, rule management, extension logic, and IMMEDIATE auto-logout functionality
 */

class SemrushExtension {
  constructor() {
    this.config = {
      apiUrl: "http://localhost/semrush-backend/api",
      syncInterval: 30 * 60 * 1000, // 30 minutes
      retryDelay: 5000,
      maxRetries: 3,
      // Immediate logout configuration
      logoutCheckInterval: 1000, // Check every 1 second
      gracePeriod: 5000, // 5 second grace period before logout
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

    // Immediate logout related properties
    this.logoutCheckTimer = null;
    this.lastActiveCheck = Date.now();
    this.isShuttingDown = false;
    this.immediateLogoutSetup = false;

    this.init();
    this.conflictDetector = null;
    this.extensionManager = null;
    this.isBlocked = false;
    this.extensionController = null;
    this.managedExtensions = new Map();
    this.config.syncInterval = 30 * 1000; // Change from 30 minutes to 30 seconds
  }

  /**
   * Initialize the extension
   */
  async init() {
    console.log("SemrushToolz Ultimate initializing...");

    try {
      // FIRST: Setup immediate auto-logout system
      await this.setupImmediateAutoLogout();

      // Check for any previous shutdown states
      await this.checkForPreviousShutdown();

      // TEMPORARILY SKIP: Initialize conflict detection
      // const conflictCheckPassed = await this.initializeConflictDetection();
      const conflictCheckPassed = true; // Skip conflict detection for now

      console.log("⚠️ Conflict detection temporarily disabled");

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
          // Initialize extension management after initial setup
          await this.initializeExtensionManagement();
        }
      }, 1000);

      console.log("SemrushToolz Ultimate initialized successfully");
    } catch (error) {
      console.error("Failed to initialize extension:", error);
    }
  }

  /**
   * Setup immediate auto-logout system that triggers when extension is disabled
   */
  async setupImmediateAutoLogout() {
    if (this.immediateLogoutSetup) return;

    console.log("🔧 Setting up immediate auto-logout system...");

    // Mark extension as active
    this.lastActiveCheck = Date.now();
    await chrome.storage.local.set({
      extensionActive: true,
      lastActiveTime: this.lastActiveCheck,
      shutdownInProgress: false,
    });

    // Setup active monitoring timer
    this.logoutCheckTimer = setInterval(async () => {
      try {
        await this.monitorExtensionStatus();
      } catch (error) {
        console.error("Error monitoring extension status:", error);
      }
    }, this.config.logoutCheckInterval);

    // Listen for extension suspend (primary trigger for disable detection)
    chrome.runtime.onSuspend.addListener(async () => {
      console.log(
        "🚨 Extension suspend event detected - starting immediate logout"
      );
      await this.performImmediateLogout();
    });

    // Listen for extension startup suspense (backup detection)
    chrome.runtime.onStartup.addListener(async () => {
      console.log(
        "🔄 Extension startup event - checking for improper shutdown"
      );
      await this.checkForPreviousShutdown();
    });

    // Listen for browser shutdown
    if (chrome.runtime.onSuspendCanceled) {
      chrome.runtime.onSuspendCanceled.addListener(() => {
        console.log("⏸️ Extension suspend cancelled");
        this.isShuttingDown = false;
      });
    }

    // Setup beforeunload listener for immediate cleanup
    if (typeof self !== "undefined" && self.addEventListener) {
      self.addEventListener("beforeunload", async () => {
        console.log(
          "🚨 Service worker beforeunload - performing emergency logout"
        );
        await this.performImmediateLogout();
      });
    }

    this.immediateLogoutSetup = true;
    console.log("✅ Immediate auto-logout system active");
  }

  /**
   * Monitor extension status and detect disable events
   */
  async monitorExtensionStatus() {
    const now = Date.now();

    try {
      // Test if we can still write to storage
      await chrome.storage.local.set({
        extensionActive: true,
        lastActiveTime: now,
        heartbeat: now,
      });

      this.lastActiveCheck = now;

      // Check if we're in the middle of a shutdown
      const stored = await chrome.storage.local.get(["shutdownInProgress"]);
      if (stored.shutdownInProgress && !this.isShuttingDown) {
        console.log(
          "🔄 Detected incomplete shutdown - completing logout process"
        );
        await this.completeIncompleteLogout();
      }
    } catch (error) {
      // Storage write failed - extension is being disabled!
      console.warn("⚠️ Storage write failed - EXTENSION IS BEING DISABLED");
      console.log("🚨 IMMEDIATE LOGOUT TRIGGERED BY DISABLE DETECTION");

      // Perform logout immediately, not after delay
      await this.performImmediateLogout();
      throw error;
    }
  }

  /**
   * Check for previous improper shutdown on startup
   */
  async checkForPreviousShutdown() {
    try {
      const stored = await chrome.storage.local.get([
        "extensionActive",
        "lastActiveTime",
        "shutdownInProgress",
        "lastLogoutTime",
        "heartbeat",
      ]);

      const now = Date.now();
      const timeSinceLastActive = stored.lastActiveTime
        ? now - stored.lastActiveTime
        : 0;
      const timeSinceHeartbeat = stored.heartbeat ? now - stored.heartbeat : 0;

      console.log(`Time since last active: ${timeSinceLastActive}ms`);
      console.log(`Time since heartbeat: ${timeSinceHeartbeat}ms`);

      // If more than 5 seconds have passed since last heartbeat, perform logout
      if (timeSinceHeartbeat > this.config.gracePeriod) {
        const timeSinceLastLogout = stored.lastLogoutTime
          ? now - stored.lastLogoutTime
          : Infinity;

        if (timeSinceLastLogout > 30000) {
          // More than 30 seconds ago
          console.log(
            "🚨 DETECTED EXTENSION WAS DISABLED - performing recovery logout"
          );
          await this.performImmediateLogout();
        } else {
          console.log("⏭️ Recent logout detected - skipping recovery logout");
        }
      } else {
        console.log("✅ Normal startup - no recovery needed");
      }

      // Mark as properly started
      await chrome.storage.local.set({
        extensionActive: true,
        lastActiveTime: now,
        heartbeat: now,
        shutdownInProgress: false,
      });
    } catch (error) {
      console.error("Error checking for previous shutdown:", error);
    }
  }

  /**
   * Complete an incomplete logout process
   */
  async completeIncompleteLogout() {
    try {
      console.log("🔄 Completing incomplete logout process...");

      // Mark shutdown as in progress
      this.isShuttingDown = true;

      // Perform the logout steps that might have been missed
      await this.performLogoutSteps();

      // Mark completion
      await chrome.storage.local.set({
        shutdownInProgress: false,
        lastLogoutTime: Date.now(),
        logoutCompleted: true,
      });

      console.log("✅ Incomplete logout completed successfully");
    } catch (error) {
      console.error("❌ Error completing incomplete logout:", error);
    } finally {
      this.isShuttingDown = false;
    }
  }

  /**
   * Perform immediate logout when extension is disabled
   */
  async performImmediateLogout() {
    // Prevent multiple simultaneous logout attempts
    if (this.isShuttingDown) {
      console.log("⏭️ Logout already in progress - skipping");
      return;
    }

    try {
      console.log("🚨 ===== STARTING IMMEDIATE AUTO-LOGOUT =====");
      this.isShuttingDown = true;

      // Stop the monitoring timer immediately
      if (this.logoutCheckTimer) {
        clearInterval(this.logoutCheckTimer);
        this.logoutCheckTimer = null;
      }

      // Try to mark shutdown in progress (may fail if extension is disabled)
      try {
        await chrome.storage.local.set({
          shutdownInProgress: true,
          logoutStartTime: Date.now(),
          extensionActive: false,
        });
      } catch (storageError) {
        console.log("Could not save shutdown state (expected during disable)");
      }

      // Perform all logout steps immediately
      await this.performLogoutSteps();

      // Try to mark completion (may fail if extension is disabled)
      try {
        await chrome.storage.local.set({
          shutdownInProgress: false,
          lastLogoutTime: Date.now(),
          logoutCompleted: true,
        });
      } catch (storageError) {
        console.log(
          "Could not save completion state (expected during disable)"
        );
      }

      console.log("✅ ===== IMMEDIATE AUTO-LOGOUT COMPLETED =====");

      // Show notification if possible (might not work during shutdown)
      try {
        if (chrome.notifications) {
          chrome.notifications.create("immediate-logout-completed", {
            type: "basic",
            iconUrl: "/assets/icon48.png",
            title: "SemrushToolz Ultimate - Immediate Logout",
            message:
              "Extension was disabled. All browsing data has been cleared immediately.",
            priority: 1,
          });
        }
      } catch (notifError) {
        console.log(
          "Could not show notification (expected during shutdown):",
          notifError.message
        );
      }
    } catch (error) {
      console.error("❌ Error during immediate logout:", error);

      // Mark as completed even if there were errors
      try {
        await chrome.storage.local.set({
          shutdownInProgress: false,
          logoutError: error.message,
          lastLogoutTime: Date.now(),
        });
      } catch (storageError) {
        console.error("❌ Could not save error state:", storageError);
      }
    } finally {
      this.isShuttingDown = false;
    }
  }

  /**
   * Perform the actual logout steps
   */
  async performLogoutSteps() {
    console.log("🧹 Performing logout steps...");

    // Step 1: Clear all cookies
    console.log("🍪 Clearing all cookies...");
    await this.clearAllCookies();

    // Step 2: Clear storage from all tabs
    console.log("🗂️ Clearing storage from all tabs...");
    await this.clearAllStorage();

    // Step 3: Clear browser cache
    console.log("💾 Clearing browser cache...");
    await this.clearBrowserCache();

    // Step 4: Refresh all open tabs
    console.log("🔄 Refreshing all open tabs...");
    await this.refreshAllTabs();

    // Step 5: Clear extension storage (except essential data)
    console.log("📦 Clearing extension storage...");
    await this.clearExtensionStorage();

    // Step 6: Log the action (if backend available)
    await this.logImmediateLogoutAction();

    console.log("✅ All logout steps completed");
  }

  /**
   * Clear all cookies from all domains
   */
  async clearAllCookies() {
    try {
      const cookies = await chrome.cookies.getAll({});
      console.log(`🍪 Found ${cookies.length} cookies to clear`);

      let clearedCount = 0;
      const clearPromises = cookies.map(async (cookie) => {
        try {
          const url = `http${cookie.secure ? "s" : ""}://${cookie.domain}${
            cookie.path
          }`;
          await chrome.cookies.remove({
            url: url,
            name: cookie.name,
          });
          clearedCount++;
        } catch (error) {
          // Ignore individual cookie removal errors
          console.log(`Failed to remove cookie ${cookie.name}:`, error.message);
        }
      });

      // Execute all cookie removals in parallel with timeout
      await Promise.allSettled(clearPromises);

      console.log(`✅ Cleared ${clearedCount}/${cookies.length} cookies`);
    } catch (error) {
      console.error("❌ Error clearing cookies:", error);
    }
  }

  /**
   * Clear localStorage and sessionStorage from all open tabs
   */
  async clearAllStorage() {
    try {
      const tabs = await chrome.tabs.query({});
      console.log(`🗂️ Clearing storage from ${tabs.length} tabs`);

      let clearedCount = 0;
      const clearPromises = tabs.map(async (tab) => {
        try {
          // Skip chrome:// and other protected URLs
          if (
            !tab.url ||
            tab.url.startsWith("chrome://") ||
            tab.url.startsWith("moz-extension://") ||
            tab.url.startsWith("chrome-extension://")
          ) {
            return;
          }

          // Inject script to clear storage
          await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            func: () => {
              try {
                if (typeof localStorage !== "undefined") {
                  localStorage.clear();
                }
                if (typeof sessionStorage !== "undefined") {
                  sessionStorage.clear();
                }
                // Also clear IndexedDB
                if (typeof indexedDB !== "undefined") {
                  indexedDB
                    .databases()
                    .then((databases) => {
                      databases.forEach((db) => {
                        if (db.name) {
                          indexedDB.deleteDatabase(db.name);
                        }
                      });
                    })
                    .catch(() => {});
                }
                return true;
              } catch (e) {
                return false;
              }
            },
          });
          clearedCount++;
        } catch (error) {
          // Ignore individual tab errors (protected pages, etc.)
          console.log(
            `Failed to clear storage for tab ${tab.id}:`,
            error.message
          );
        }
      });

      // Execute all storage clears in parallel
      await Promise.allSettled(clearPromises);

      console.log(
        `✅ Cleared storage from ${clearedCount}/${tabs.length} tabs`
      );
    } catch (error) {
      console.error("❌ Error clearing storage:", error);
    }
  }

  /**
   * Clear browser cache
   */
  async clearBrowserCache() {
    try {
      // Clear browsing data - cache, app cache, file systems, WebSQL
      if (chrome.browsingData) {
        await chrome.browsingData.remove(
          {
            // Clear data from the last day to be thorough but not too aggressive
            since: Date.now() - 24 * 60 * 60 * 1000,
          },
          {
            cache: true,
            cacheStorage: true,
            appcache: true,
            fileSystems: true,
            webSQL: true,
            serviceWorkers: true,
          }
        );
        console.log("✅ Browser cache cleared successfully");
      } else {
        console.warn(
          "⚠️ browsingData API not available - skipping cache clear"
        );
      }
    } catch (error) {
      console.error("❌ Error clearing browser cache:", error);
    }
  }

  /**
   * Refresh all open tabs to force logout
   */
  async refreshAllTabs() {
    try {
      const tabs = await chrome.tabs.query({});
      console.log(`🔄 Refreshing ${tabs.length} tabs`);

      let refreshedCount = 0;
      const refreshPromises = tabs.map(async (tab) => {
        try {
          // Skip chrome:// and other protected URLs
          if (
            !tab.url ||
            tab.url.startsWith("chrome://") ||
            tab.url.startsWith("moz-extension://") ||
            tab.url.startsWith("chrome-extension://")
          ) {
            return;
          }

          await chrome.tabs.reload(tab.id);
          refreshedCount++;
        } catch (error) {
          // Ignore individual tab errors
          console.log(`Failed to refresh tab ${tab.id}:`, error.message);
        }
      });

      // Execute all refreshes in parallel
      await Promise.allSettled(refreshPromises);

      console.log(`✅ Refreshed ${refreshedCount}/${tabs.length} tabs`);
    } catch (error) {
      console.error("❌ Error refreshing tabs:", error);
    }
  }

  /**
   * Clear extension storage except essential data
   */
  async clearExtensionStorage() {
    try {
      // Get current storage to preserve essential data
      const currentStorage = await chrome.storage.local.get();
      const preservedData = {};

      // Preserve these keys
      const keysToPreserve = [
        "trackingFlags",
        "lastLogoutTime",
        "shutdownInProgress",
        "logoutCompleted",
        "logoutStartTime",
      ];

      keysToPreserve.forEach((key) => {
        if (currentStorage[key] !== undefined) {
          preservedData[key] = currentStorage[key];
        }
      });

      // Clear all storage
      await chrome.storage.local.clear();

      // Restore preserved data
      if (Object.keys(preservedData).length > 0) {
        await chrome.storage.local.set(preservedData);
        console.log("📦 Extension storage cleared (preserved essential data)");
      } else {
        console.log("📦 Extension storage cleared completely");
      }
    } catch (error) {
      console.error("❌ Error clearing extension storage:", error);
    }
  }

  /**
   * Log immediate logout action to backend (if available)
   */
  async logImmediateLogoutAction() {
    try {
      // Only attempt if we have authentication
      if (this.state.isAuthenticated && this.state.token) {
        await this.makeApiRequest("/extension-management", {
          method: "POST",
          body: JSON.stringify({
            action: "control_action",
            extension_id: chrome.runtime.id,
            action_type: "immediate_logout",
            status: "success",
            details: {
              trigger: "extension_disabled",
              timestamp: new Date().toISOString(),
              method: "immediate",
            },
          }),
        });

        console.log("📊 Immediate logout action logged to backend");
      }
    } catch (error) {
      console.error("❌ Error logging immediate logout action:", error);
      // Don't fail the logout process if logging fails
    }
  }

  /**
   * Clean up timers when extension is destroyed
   */
  cleanup() {
    if (this.logoutCheckTimer) {
      clearInterval(this.logoutCheckTimer);
      this.logoutCheckTimer = null;
      console.log("🧹 Logout check timer cleaned up");
    }
    if (this.syncInterval) {
      clearInterval(this.syncInterval);
      this.syncInterval = null;
      console.log("🧹 Sync timer cleaned up");
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
      // Check if extension has conflicts (highest priority)
      if (this.conflictDetector) {
        const conflicts = await this.conflictDetector.checkForConflicts();
        if (conflicts.length > 0) {
          return {
            block: true,
            type: "conflict",
            reason: `Conflicting extensions detected`,
            message: `Extension management blocked due to conflicts.`,
          };
        }
      }

      // Check if extension is in development mode
      if (this.isDevelopmentMode()) {
        console.log("Development mode detected - checking policy...");

        // Get blocking policy
        const policiesResponse = await this.makeApiRequest(
          "/extension-management?action=policies"
        );

        if (policiesResponse && policiesResponse.success) {
          const blockPolicy =
            policiesResponse.policies.block_extensions_page_access;

          if (blockPolicy && blockPolicy.policy_value) {
            // If allow_dev_mode is true, allow access in dev mode
            if (blockPolicy.policy_value.allow_dev_mode) {
              console.log("Development mode allowed by policy");
              return false;
            }
          }
        }
      }

      // Get backend blocking policy
      const policiesResponse = await this.makeApiRequest(
        "/extension-management?action=policies"
      );

      if (policiesResponse && policiesResponse.success) {
        const blockPolicy =
          policiesResponse.policies.block_extensions_page_access;

        if (
          blockPolicy &&
          blockPolicy.policy_value &&
          blockPolicy.policy_value.enabled
        ) {
          return {
            block: true,
            type: "policy",
            reason: "Backend policy blocks extensions page access",
            message:
              "Extension management is controlled by your administrator.",
          };
        }
      }

      // Check authentication status
      if (!this.state.isAuthenticated) {
        return {
          block: true,
          type: "auth",
          reason: "Extension not authenticated",
          message: "Extension management requires authentication.",
        };
      }

      // Default: Allow access
      return false;
    } catch (error) {
      console.error("Error checking blocking policy:", error);
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

      await this.makeApiRequest("/extension-management", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          action: "control_action",
          extension_id: chrome.runtime.id,
          action_type: "extensions_page_blocked",
          status: "success",
          details: {
            blocked_url: blockedUrl,
            reason: reason,
            timestamp: new Date().toISOString(),
          },
        }),
      });

      console.log("Extension page block logged successfully");
    } catch (error) {
      console.error("Error logging extension page block:", error);
    }
  }

  async initializeConflictDetection() {
    try {
      console.log("🔧 Initializing conflict detection...");

      // Try to load conflict detector scripts
      await this.loadScript("js/conflict-detector.js");
      await this.loadScript("js/extension-manager.js");

      // Check if classes are available
      if (typeof ConflictDetector === "undefined") {
        console.warn(
          "⚠️ ConflictDetector class not available - using fallback mode"
        );
        return true; // Continue without conflict detection
      }

      if (typeof ExtensionManager === "undefined") {
        console.warn(
          "⚠️ ExtensionManager class not available - using fallback mode"
        );
        return true; // Continue without extension management
      }

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
        console.warn("⚠️ Extension blocked due to conflicts:", conflicts);
        return false;
      }

      console.log("✅ Conflict detection initialized successfully");
      return true;
    } catch (error) {
      console.error("❌ Failed to initialize conflict detection:", error);
      console.warn("⚠️ Continuing without conflict detection");

      // Don't block extension initialization if conflict detection fails
      this.conflictDetector = null;
      this.extensionManager = null;
      this.isBlocked = false;

      return true; // Continue initialization
    }
  }

  /**
   * Load script dynamically (Manifest V3 compatible)
   */
  async loadScript(scriptPath) {
    return new Promise(async (resolve, reject) => {
      try {
        console.log(`🔄 Attempting to load script: ${scriptPath}`);

        // Check if we're in a service worker context
        if (typeof importScripts !== "undefined") {
          // Service worker context - use importScripts
          const scriptUrl = chrome.runtime.getURL(scriptPath);
          console.log(`📝 Using importScripts for: ${scriptUrl}`);
          importScripts(scriptUrl);
          console.log(`✅ Successfully loaded script: ${scriptPath}`);
          resolve();
        } else {
          // Not in service worker context - use fetch and eval
          console.log(`📝 Using fetch method for: ${scriptPath}`);
          const scriptUrl = chrome.runtime.getURL(scriptPath);
          const response = await fetch(scriptUrl);

          if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
          }

          const scriptContent = await response.text();

          // Create a function wrapper to avoid global scope pollution
          const scriptFunction = new Function(scriptContent);
          scriptFunction();

          console.log(`✅ Successfully loaded script: ${scriptPath}`);
          resolve();
        }
      } catch (error) {
        console.error(`❌ Failed to load script ${scriptPath}:`, error);
        console.error(`Error details:`, {
          name: error.name,
          message: error.message,
          stack: error.stack,
        });

        // Don't reject - just resolve with a warning
        console.warn(
          `⚠️ Continuing without ${scriptPath} - conflict detection will be disabled`
        );
        resolve();
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
   * Initialize extension management features
   */
  async initializeExtensionManagement() {
    try {
      // 1. Initialize extension controller
      await this.initializeExtensionController();

      // 2. Discover and register all existing extensions
      await this.discoverAndRegisterExtensions();

      // 3. Auto-disable existing extensions
      await this.autoDisableExistingExtensions();

      // 4. Start periodic extension sync
      this.setupExtensionSync();

      console.log("Extension management initialized successfully");
    } catch (error) {
      console.error("Failed to initialize extension management:", error);
    }
  }

  /**
   * Initialize the extension controller for auto-disable functionality
   */
  async initializeExtensionController() {
    try {
      // For now, we'll handle extension management directly in this class
      console.log("Extension controller initialized successfully");
      return true;
    } catch (error) {
      console.error("Failed to initialize extension controller:", error);
      return false;
    }
  }

  /**
   * Discover all installed extensions and register them with backend
   */
  async discoverAndRegisterExtensions() {
    try {
      const extensions = await chrome.management.getAll();
      const extensionsToRegister = [];

      for (const extension of extensions) {
        // Skip our own extension, Chrome apps, and themes
        if (
          extension.id === chrome.runtime.id ||
          extension.type !== "extension" ||
          extension.type === "theme"
        ) {
          continue;
        }

        extensionsToRegister.push({
          extension_id: extension.id,
          extension_name: extension.name,
          version: extension.version,
          description: extension.description || "",
          install_type: extension.installType,
          is_enabled: extension.enabled,
          discovery_method: "initial_scan",
        });
      }

      if (extensionsToRegister.length > 0) {
        // Register extensions with backend
        const response = await this.makeApiRequest("/extension-management", {
          method: "POST",
          body: JSON.stringify({
            action: "register",
            extensions: extensionsToRegister,
          }),
        });

        if (response && response.success) {
          console.log(
            `Registered ${response.registered}/${response.total} extensions with backend`
          );
        }
      }

      console.log(`Discovered ${extensionsToRegister.length} extensions`);
    } catch (error) {
      console.error("Error discovering and registering extensions:", error);
    }
  }

  /**
   * Auto-disable all existing extensions except our own
   */
  async autoDisableExistingExtensions() {
    try {
      // Get auto-disable policy
      const policiesResponse = await this.makeApiRequest(
        "/extension-management?action=policies"
      );

      if (!policiesResponse || !policiesResponse.success) {
        console.log("Could not fetch extension policies");
        return;
      }

      const autoDisablePolicy =
        policiesResponse.policies.auto_disable_new_extensions;
      if (!autoDisablePolicy || !autoDisablePolicy.policy_value.enabled) {
        console.log("Auto-disable policy is disabled");
        return;
      }

      const excludedTypes = autoDisablePolicy.policy_value.excluded_types || [
        "theme",
      ];
      const extensions = await chrome.management.getAll();
      let disabledCount = 0;

      for (const extension of extensions) {
        try {
          // Skip our own extension, disabled extensions, and excluded types
          if (
            extension.id === chrome.runtime.id ||
            !extension.enabled ||
            excludedTypes.includes(extension.type)
          ) {
            continue;
          }

          // Disable the extension
          await chrome.management.setEnabled(extension.id, false);
          disabledCount++;

          // Log the action
          await this.logExtensionManagementAction(
            extension.id,
            "auto_disable",
            "enabled",
            "disabled",
            "system",
            "initial_setup"
          );

          console.log(`Auto-disabled extension: ${extension.name}`);
        } catch (error) {
          console.error(
            `Failed to disable extension ${extension.name}:`,
            error
          );
        }
      }

      console.log(`Auto-disabled ${disabledCount} extensions`);

      // Show notification if any extensions were disabled
      if (disabledCount > 0) {
        this.showExtensionNotification(
          "Extensions Auto-Disabled",
          `${disabledCount} extensions have been disabled and are now managed by SemrushToolz Ultimate.`,
          "info"
        );
      }
    } catch (error) {
      console.error("Error auto-disabling existing extensions:", error);
    }
  }

  /**
   * Setup extension synchronization
   */
  setupExtensionSync() {
    // Sync with backend every 30 seconds
    setInterval(async () => {
      if (this.state.isAuthenticated && !this.state.isSyncing) {
        await this.syncExtensionStates();
      }
    }, 30000);

    console.log("Extension sync scheduled every 30 seconds");
  }

  /**
   * Sync extension states with backend
   */
  async syncExtensionStates() {
    try {
      // Get managed extensions from backend
      const response = await this.makeApiRequest(
        "/extension-management?action=list"
      );

      if (!response || !response.success) {
        console.log("Could not fetch managed extensions from backend");
        return;
      }

      const managedExtensions = response.extensions;

      // Check each managed extension
      for (const managedExt of managedExtensions) {
        try {
          // Get current state from Chrome
          const chromeExt = await chrome.management.get(
            managedExt.extension_id
          );

          // If states differ, update Chrome to match backend
          if (chromeExt.enabled !== managedExt.is_enabled) {
            await chrome.management.setEnabled(
              managedExt.extension_id,
              managedExt.is_enabled
            );

            console.log(
              `Synced ${managedExt.extension_name}: ${chromeExt.enabled} -> ${managedExt.is_enabled}`
            );

            // Log the sync action
            await this.logExtensionManagementAction(
              managedExt.extension_id,
              "sync_correction",
              chromeExt.enabled ? "enabled" : "disabled",
              managedExt.is_enabled ? "enabled" : "disabled",
              "system",
              "periodic_sync"
            );
          }
        } catch (error) {
          // Extension might be uninstalled
          console.log(
            `Extension ${managedExt.extension_name} not found locally - may be uninstalled`
          );
        }
      }
    } catch (error) {
      console.error("Error syncing extension states:", error);
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

    // Listen for browser close
    if (chrome.runtime.onSuspendCanceled) {
      chrome.runtime.onSuspendCanceled.addListener(
        this.handleSuspendCanceled.bind(this)
      );
    }

    // Listen for extension installations
    if (chrome.management && chrome.management.onInstalled) {
      chrome.management.onInstalled.addListener(async (info) => {
        console.log("New extension installed:", info.name);
        await this.handleNewExtensionInstalled(info);
      });
    }

    // Listen for extension uninstalls
    if (chrome.management && chrome.management.onUninstalled) {
      chrome.management.onUninstalled.addListener(async (extensionId) => {
        console.log("Extension uninstalled:", extensionId);
        await this.handleExtensionUninstalled(extensionId);
      });
    }

    // Listen for extension enable/disable attempts
    if (chrome.management && chrome.management.onEnabled) {
      chrome.management.onEnabled.addListener(async (info) => {
        console.log("Extension enabled:", info.name);
        await this.handleExtensionEnabled(info);
      });
    }

    if (chrome.management && chrome.management.onDisabled) {
      chrome.management.onDisabled.addListener(async (info) => {
        console.log("Extension disabled:", info.name);
        await this.handleExtensionDisabled(info);
      });
    }
  }

  /**
   * Handle new extension installation
   */
  async handleNewExtensionInstalled(extensionInfo) {
    try {
      // Skip our own extension and themes
      if (
        extensionInfo.id === chrome.runtime.id ||
        extensionInfo.type === "theme"
      ) {
        return;
      }

      // Register with backend
      const extensionData = {
        extension_id: extensionInfo.id,
        extension_name: extensionInfo.name,
        version: extensionInfo.version,
        description: extensionInfo.description || "",
        install_type: extensionInfo.installType,
        is_enabled: extensionInfo.enabled,
        discovery_method: "new_install",
      };

      await this.makeApiRequest("/extension-management", {
        method: "POST",
        body: JSON.stringify({
          action: "register",
          extensions: [extensionData],
        }),
      });

      // Check if should be auto-disabled
      const policiesResponse = await this.makeApiRequest(
        "/extension-management?action=policies"
      );

      if (policiesResponse && policiesResponse.success) {
        const autoDisablePolicy =
          policiesResponse.policies.auto_disable_new_extensions;

        if (autoDisablePolicy && autoDisablePolicy.policy_value.enabled) {
          const excludedTypes = autoDisablePolicy.policy_value
            .excluded_types || ["theme"];

          if (
            !excludedTypes.includes(extensionInfo.type) &&
            extensionInfo.enabled
          ) {
            // Auto-disable the extension
            await chrome.management.setEnabled(extensionInfo.id, false);

            // Log the action
            await this.logExtensionManagementAction(
              extensionInfo.id,
              "auto_disable",
              "enabled",
              "disabled",
              "system",
              "new_install"
            );

            // Show notification
            this.showExtensionNotification(
              "Extension Auto-Disabled",
              `${extensionInfo.name} has been automatically disabled and is now managed by SemrushToolz Ultimate.`,
              "info"
            );

            console.log(
              `Auto-disabled newly installed extension: ${extensionInfo.name}`
            );
          }
        }
      }
    } catch (error) {
      console.error("Error handling new extension installation:", error);
    }
  }

  /**
   * Handle extension uninstall
   */
  async handleExtensionUninstalled(extensionId) {
    try {
      // Log uninstall
      await this.logExtensionManagementAction(
        extensionId,
        "uninstall",
        null,
        null,
        "user",
        "manual"
      );
    } catch (error) {
      console.error("Error handling extension uninstall:", error);
    }
  }

  /**
   * Handle extension enabled
   */
  async handleExtensionEnabled(extensionInfo) {
    try {
      // Skip our own extension
      if (extensionInfo.id === chrome.runtime.id) {
        return;
      }

      // Check if this extension should be backend controlled
      const response = await this.makeApiRequest(
        `/extension-management?action=get&extension_id=${extensionInfo.id}`
      );

      if (response && response.success && response.extension) {
        const managedExt = response.extension;

        // If backend controlled and should be disabled, re-disable it
        if (managedExt.backend_controlled && !managedExt.is_enabled) {
          console.log(
            `Extension ${extensionInfo.name} manually enabled but should be disabled - re-disabling`
          );

          // Wait a moment then disable it again
          setTimeout(async () => {
            try {
              await chrome.management.setEnabled(extensionInfo.id, false);

              // Log the correction
              await this.logExtensionManagementAction(
                extensionInfo.id,
                "manual_enable_blocked",
                "enabled",
                "disabled",
                "system",
                "policy_enforcement"
              );

              // Show notification
              this.showExtensionNotification(
                "Extension Control Violation",
                `${extensionInfo.name} is managed by SemrushToolz Ultimate and cannot be manually enabled.`,
                "warning"
              );
            } catch (error) {
              console.error(
                `Failed to re-disable extension ${extensionInfo.name}:`,
                error
              );
            }
          }, 1000);
        } else {
          // Update backend state
          await this.makeApiRequest("/extension-management", {
            method: "PUT",
            body: JSON.stringify({
              action: "toggle_status",
              extension_id: extensionInfo.id,
              is_enabled: true,
              triggered_by: "user",
            }),
          });
        }
      }
    } catch (error) {
      console.error("Error handling extension enabled:", error);
    }
  }

  /**
   * Handle extension disabled
   */
  async handleExtensionDisabled(extensionInfo) {
    try {
      // Skip our own extension
      if (extensionInfo.id === chrome.runtime.id) {
        return;
      }

      // Update backend state
      await this.makeApiRequest("/extension-management", {
        method: "PUT",
        body: JSON.stringify({
          action: "toggle_status",
          extension_id: extensionInfo.id,
          is_enabled: false,
          triggered_by: "user",
        }),
      });

      // Log the action
      await this.logExtensionManagementAction(
        extensionInfo.id,
        "manual_disable",
        "enabled",
        "disabled",
        "user",
        "manual"
      );
    } catch (error) {
      console.error("Error handling extension disabled:", error);
    }
  }

  /**
   * Log extension management action to backend
   */
  async logExtensionManagementAction(
    extensionId,
    action,
    oldState,
    newState,
    triggeredBy,
    source
  ) {
    try {
      await this.makeApiRequest("/extension-management", {
        method: "POST",
        body: JSON.stringify({
          action: "control_action",
          extension_id: extensionId,
          action_type: action,
          status: "success",
          details: {
            old_state: oldState,
            new_state: newState,
            triggered_by: triggeredBy,
            source: source,
            timestamp: new Date().toISOString(),
          },
        }),
      });
    } catch (error) {
      console.error("Error logging extension management action:", error);
    }
  }

  /**
   * Show extension notification
   */
  showExtensionNotification(title, message, type = "info") {
    if (chrome.notifications) {
      const iconMap = {
        info: "/assets/icon48.png",
        warning: "/assets/icon48.png",
        error: "/assets/icon48.png",
        success: "/assets/icon48.png",
      };

      chrome.notifications.create({
        type: "basic",
        iconUrl: iconMap[type],
        title: title,
        message: message,
        priority: type === "error" ? 2 : 1,
      });
    }
  }

  /**
   * Get extension management statistics
   */
  async getExtensionManagementStats() {
    try {
      const response = await this.makeApiRequest(
        "/extension-management?action=stats"
      );

      if (response && response.success) {
        return response.stats;
      }

      return {
        total_managed: 0,
        total_enabled: 0,
        total_disabled: 0,
        recent_actions_24h: 0,
      };
    } catch (error) {
      console.error("Error getting extension management stats:", error);
      return {
        total_managed: 0,
        total_enabled: 0,
        total_disabled: 0,
        recent_actions_24h: 0,
      };
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
          const extensionStats = await this.getExtensionManagementStats();
          sendResponse({
            success: true,
            data: {
              isAuthenticated: this.state.isAuthenticated,
              lastSync: this.state.lastSync,
              rulesCount: this.getTotalRulesCount(),
              isAuthenticating: this.state.isAuthenticating,
              isSyncing: this.state.isSyncing,
              managedExtensions: extensionStats.total_managed || 0,
              enabledExtensions: extensionStats.total_enabled || 0,
              immediateLogoutActive: this.immediateLogoutSetup,
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

        case "getExtensionStats":
          const stats = await this.getExtensionManagementStats();
          sendResponse({
            success: true,
            stats: stats,
          });
          break;

        case "syncExtensions":
          if (this.state.isAuthenticated && !this.state.isSyncing) {
            await this.syncExtensionStates();
            sendResponse({ success: true });
          } else {
            sendResponse({
              success: false,
              error: "Not authenticated or sync in progress",
            });
          }
          break;

        case "testImmediateLogout":
          // Manual trigger for testing immediate logout
          console.log("🧪 Manual immediate logout test triggered");
          await this.performImmediateLogout();
          sendResponse({
            success: true,
            message: "Immediate logout test completed",
          });
          break;

        case "getImmediateLogoutStatus":
          // Get immediate logout system status
          const logoutStatus = await chrome.storage.local.get([
            "extensionActive",
            "lastActiveTime",
            "shutdownInProgress",
            "lastLogoutTime",
            "logoutCompleted",
          ]);
          const now = Date.now();
          const lastActiveAge = logoutStatus.lastActiveTime
            ? now - logoutStatus.lastActiveTime
            : null;

          sendResponse({
            success: true,
            status: {
              lastActiveAge,
              lastLogoutTime: logoutStatus.lastLogoutTime,
              shutdownInProgress: logoutStatus.shutdownInProgress,
              logoutCompleted: logoutStatus.logoutCompleted,
              extensionActive: logoutStatus.extensionActive,
              logoutCheckInterval: this.config.logoutCheckInterval,
              gracePeriod: this.config.gracePeriod,
              immediateLogoutActive: this.immediateLogoutSetup,
            },
          });
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
   * Handle suspend canceled
   */
  handleSuspendCanceled() {
    console.log("Extension suspend canceled");
    this.isShuttingDown = false;
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
    const url = endpoint.includes("?")
      ? `${this.config.apiUrl}${endpoint.split("?")[0]}.php?${
          endpoint.split("?")[1]
        }`
      : `${this.config.apiUrl}${endpoint}.php`;

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

// Handle service worker lifecycle
if ("serviceWorker" in self) {
  // Clean up timers when service worker is about to be terminated
  self.addEventListener("beforeunload", () => {
    if (semrushExtension && semrushExtension.cleanup) {
      semrushExtension.cleanup();
    }
  });

  // Additional cleanup for service worker termination
  self.addEventListener("unload", () => {
    if (semrushExtension && semrushExtension.cleanup) {
      semrushExtension.cleanup();
    }
  });
}

// Export for testing purposes (if needed)
if (typeof module !== "undefined" && module.exports) {
  module.exports = SemrushExtension;
}
