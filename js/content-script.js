/**
 * SemrushToolz Ultimate - Content Script
 * Handles CSS modifications and rule application on web pages
 */

class SemrushContentScript {
  constructor() {
    this.cssRules = [];
    this.appliedRules = new Set();
    this.observer = null;
    this.isInitialized = false;

    this.init();
  }

  /**
   * Initialize content script
   */
  async init() {
    // Wait for DOM to be ready
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", () => this.setup());
    } else {
      this.setup();
    }
  }

  /**
   * Setup content script after DOM is ready
   */
  async setup() {
    try {
      // Load CSS rules from storage
      await this.loadCssRules();

      // Apply initial rules
      this.applyCssRules();

      // Setup mutation observer for dynamic content
      this.setupMutationObserver();

      // Listen for rule updates from background script
      this.setupMessageListener();

      // Setup periodic rule refresh
      this.setupPeriodicRefresh();

      this.isInitialized = true;
      console.log("SemrushToolz Content Script initialized");
    } catch (error) {
      console.error("Error initializing content script:", error);
    }
  }

  /**
   * Load CSS rules from storage
   */
  async loadCssRules() {
    return new Promise((resolve) => {
      chrome.storage.local.get(["rules"], (data) => {
        if (data.rules && data.rules.cssRules) {
          this.cssRules = this.filterRelevantRules(data.rules.cssRules);
          console.log(`Loaded ${this.cssRules.length} CSS rules for this page`);
        }
        resolve();
      });
    });
  }

  /**
   * Filter rules relevant to current page
   */
  filterRelevantRules(allRules) {
    const currentUrl = window.location.href;

    return allRules.filter((rule) => {
      if (!rule.is_active) return false;

      try {
        // Handle different pattern formats
        let pattern = rule.url_pattern || rule.urlPattern;
        if (!pattern) return false;

        // Convert wildcard patterns to regex
        if (pattern.includes("*")) {
          pattern = pattern
            .replace(/[.+?^${}()|[\]\\]/g, "\\$&")
            .replace(/\*/g, ".*");
        }

        // Test pattern against current URL
        const regex = new RegExp(pattern, "i");
        return regex.test(currentUrl);
      } catch (error) {
        console.error("Invalid URL pattern:", pattern, error);
        return false;
      }
    });
  }

  /**
   * Apply CSS rules to the page
   */
  applyCssRules() {
    this.cssRules.forEach((rule) => {
      try {
        this.applyRule(rule);
      } catch (error) {
        console.error("Error applying CSS rule:", rule, error);
      }
    });
  }

  /**
   * Apply a single CSS rule
   */
  applyRule(rule) {
    const ruleId = `rule-${rule.id || this.generateRuleId(rule)}`;

    // Skip if already applied
    if (this.appliedRules.has(ruleId)) return;

    const elements = document.querySelectorAll(rule.selector);
    if (elements.length === 0) return;

    switch (rule.action) {
      case "hide":
        this.hideElements(elements);
        break;

      case "remove":
        this.removeElements(elements);
        break;

      case "modify":
        this.modifyElements(elements, rule);
        break;

      default:
        console.warn("Unknown rule action:", rule.action);
    }

    this.appliedRules.add(ruleId);
    console.log(
      `Applied ${rule.action} rule to ${elements.length} elements:`,
      rule.selector
    );
  }

  /**
   * Hide elements
   */
  hideElements(elements) {
    elements.forEach((element) => {
      // Store original display value
      if (!element.dataset.semrushOriginalDisplay) {
        element.dataset.semrushOriginalDisplay =
          window.getComputedStyle(element).display;
      }
      element.style.display = "none";
      element.setAttribute("data-semrush-hidden", "true");
    });
  }

  /**
   * Remove elements from DOM
   */
  removeElements(elements) {
    elements.forEach((element) => {
      // Store reference to parent for potential restoration
      element.dataset.semrushParent = element.parentNode?.tagName || "";
      element.dataset.semrushNextSibling = element.nextSibling?.tagName || "";
      element.style.display = "none";
      element.setAttribute("data-semrush-removed", "true");

      // Actually remove from DOM
      if (element.parentNode) {
        element.parentNode.removeChild(element);
      }
    });
  }

  /**
   * Modify elements with custom CSS
   */
  modifyElements(elements, rule) {
    // Get CSS properties from rule
    let cssProperties = rule.cssProperties || rule.css_properties;

    if (!cssProperties) return;

    // Parse CSS properties if it's a string
    if (typeof cssProperties === "string") {
      try {
        cssProperties = JSON.parse(cssProperties);
      } catch (error) {
        console.error("Error parsing CSS properties:", cssProperties, error);
        return;
      }
    }

    elements.forEach((element) => {
      // Store original styles
      if (!element.dataset.semrushOriginalStyles) {
        const originalStyles = {};
        Object.keys(cssProperties).forEach((property) => {
          originalStyles[property] = element.style[property] || "";
        });
        element.dataset.semrushOriginalStyles = JSON.stringify(originalStyles);
      }

      // Apply new styles
      Object.entries(cssProperties).forEach(([property, value]) => {
        // Convert kebab-case to camelCase
        const camelProperty = property.replace(/-([a-z])/g, (match, letter) =>
          letter.toUpperCase()
        );
        element.style[camelProperty] = value;
      });

      element.setAttribute("data-semrush-modified", "true");
    });
  }

  /**
   * Generate rule ID for rules without ID
   */
  generateRuleId(rule) {
    return btoa(
      JSON.stringify({
        selector: rule.selector,
        action: rule.action,
        pattern: rule.url_pattern || rule.urlPattern,
      })
    )
      .replace(/[^a-zA-Z0-9]/g, "")
      .substring(0, 10);
  }

  /**
   * Setup mutation observer for dynamic content
   */
  setupMutationObserver() {
    if (!window.MutationObserver) {
      console.warn("MutationObserver not supported");
      return;
    }

    this.observer = new MutationObserver((mutations) => {
      let shouldReapply = false;

      mutations.forEach((mutation) => {
        if (mutation.type === "childList" && mutation.addedNodes.length > 0) {
          // Check if any added nodes are significant (not just text nodes)
          const hasSignificantNodes = Array.from(mutation.addedNodes).some(
            (node) => node.nodeType === Node.ELEMENT_NODE
          );

          if (hasSignificantNodes) {
            shouldReapply = true;
          }
        }
      });

      if (shouldReapply) {
        // Debounce reapplication
        clearTimeout(this.reapplyTimeout);
        this.reapplyTimeout = setTimeout(() => {
          this.applyCssRules();
        }, 250);
      }
    });

    // Start observing
    this.observer.observe(document.body, {
      childList: true,
      subtree: true,
    });
  }

  /**
   * Setup message listener for communication with background script
   */
  setupMessageListener() {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message.action === "updateRules") {
        this.handleRulesUpdate(message.cssRules);
        sendResponse({ success: true });
      }

      return true;
    });
  }

  /**
   * Handle rules update from background script
   */
  async handleRulesUpdate(newCssRules) {
    console.log("Received rules update from background script");

    // Clear applied rules tracking
    this.appliedRules.clear();

    // Update rules
    this.cssRules = this.filterRelevantRules(newCssRules || []);

    // Reapply rules
    this.applyCssRules();
  }

  /**
   * Setup periodic refresh of rules
   */
  setupPeriodicRefresh() {
    // Refresh rules every 5 minutes
    setInterval(async () => {
      await this.loadCssRules();
      this.applyCssRules();
    }, 5 * 60 * 1000);
  }

  /**
   * Restore all modifications (useful for debugging)
   */
  restoreAll() {
    // Restore hidden elements
    document.querySelectorAll("[data-semrush-hidden]").forEach((element) => {
      const originalDisplay = element.dataset.semrushOriginalDisplay || "block";
      element.style.display = originalDisplay;
      element.removeAttribute("data-semrush-hidden");
      delete element.dataset.semrushOriginalDisplay;
    });

    // Restore modified elements
    document.querySelectorAll("[data-semrush-modified]").forEach((element) => {
      if (element.dataset.semrushOriginalStyles) {
        try {
          const originalStyles = JSON.parse(
            element.dataset.semrushOriginalStyles
          );
          Object.entries(originalStyles).forEach(([property, value]) => {
            const camelProperty = property.replace(
              /-([a-z])/g,
              (match, letter) => letter.toUpperCase()
            );
            element.style[camelProperty] = value;
          });
        } catch (error) {
          console.error("Error restoring styles:", error);
        }
      }
      element.removeAttribute("data-semrush-modified");
      delete element.dataset.semrushOriginalStyles;
    });

    // Clear applied rules
    this.appliedRules.clear();

    console.log("All SemrushToolz modifications restored");
  }
}

// Initialize content script
let semrushContentScript;

// Ensure script runs only once per page
if (!window.semrushContentScriptLoaded) {
  window.semrushContentScriptLoaded = true;
  semrushContentScript = new SemrushContentScript();
}

// Expose restoration function for debugging
window.semrushRestore = () => {
  if (semrushContentScript) {
    semrushContentScript.restoreAll();
  }
};

// Handle errors gracefully
window.addEventListener("error", (event) => {
  if (
    event.error &&
    event.error.stack &&
    event.error.stack.includes("SemrushContentScript")
  ) {
    console.error("SemrushToolz Content Script Error:", event.error);
  }
});

// Clean up on page unload
window.addEventListener("beforeunload", () => {
  if (semrushContentScript && semrushContentScript.observer) {
    semrushContentScript.observer.disconnect();
  }
});
