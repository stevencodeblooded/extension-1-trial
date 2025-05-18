/**
 * SemrushToolz Ultimate - Extension Conflict Detector
 * Detects and handles conflicting browser extensions
 */

class ConflictDetector {
  constructor() {
    this.conflictingExtensions = new Map([
      // Cookie Management Extensions
      ["fngmhnnpilhplaeedifhccceomclgfbg", "EditThisCookie"],
      ["hhojmcideegghqohhfcidlbnkgchpajgn", "Web Developer"],
      ["bfbmjmiodbnnpllbbbfblcplfjjepjdn", "Session Manager"],
      ["cjpalhdlnbpafiamejdnhcphjbkeiagm", "uBlock Origin"],
      ["gighmmpiobklfepjocnamgkkbiglidom", "AdBlock"],
      ["cfhdojbkjhnklbpkdaibdccddilifddb", "Adblock Plus"],
      ["dmkamcknogkgcdfhhbddcghachkejeap", "Keka"],

      // Privacy Extensions
      ["jlmpjdjjbgclbocgajdjefcidcncaied", "ClearURLs"],
      ["fhcgjolkccmbidfldomjliifgaodjagh", "Cookie AutoDelete"],
      ["ldpochfhpslkijphhbnpigkbjgejgnag", "CookieBlock"],
      ["ifdepgnnjaidhhpbiacfknaiklleclhp", "Privacy Cleaner Pro"],
      ["bkdgflcldnnnapblkhphbgpggdiikppg", "DuckDuckGo Privacy Essentials"],

      // Ad Blockers
      ["aapbdbdomjkkjkaonfhkkikfgjllcleb", "Ghostery"],
      ["mlomiejdfkolichcflejclcbmpeaniij", "Ghostery"],
      ["pkehgijcmpdhfbdbbnkijodmdjhbjlgp", "Privacy Badger"],
      ["boadgeojelhgndaghljhdicfkmllpafd", "AdBlock"],
      ["gighmmpiobklfepjocnamgkkbiglidom", "AdBlock"],

      // Cookie Editors
      ["hhojmcideegghqohhfcidlbnkgchpajgn", "Cookie Editor"],
      ["fngmhnnpilhplaeedifhccceomclgfbg", "EditThisCookie"],
      ["jiaojkejmjfiojiomnkdommeodcnl", "Cookie Editor Pro"],

      // Developer Tools
      ["bfbmjmiodbnnpllbbbfblcplfjjepjdn", "Web Developer Toolbar"],
      ["ljjemllljcmogpfapbkkighbhhppjdbg", "Chrome DevTools"],

      // Privacy & Security
      ["kcnhkahbjbkbpngjhlhmellmfoopdijm", "Avira Browser Safety"],
      ["jlicmakdihplkagblhpjomaknkeojaoa", "Avast Online Security"],
      ["igopjcpkhnlhmbloglbdafciddojeepj", "Kaspersky Security Cloud"],

      // Anti-tracking
      ["ojkchikaholjmcnefhjlbohackpeeknd", "AdBlock Plus"],
      ["cjpalhdlnbpafiamejdnhcphjbkeiagm", "uBlock Origin"],
      ["gighmmpiobklfepjocnamgkkbiglidom", "AdBlock"],
      ["dbepggeogbaibhgnhhndojpepiihcmeb", "Vimium"],
    ]);

    this.violationShown = false;
    this.isBlocked = false;
  }

  /**
   * Check for conflicting extensions
   */
  async checkForConflicts() {
    try {
      const installedExtensions = await chrome.management.getAll();
      const conflicts = [];

      for (const extension of installedExtensions) {
        // Skip our own extension and Chrome apps
        if (
          extension.id === chrome.runtime.id ||
          extension.type !== "extension" ||
          !extension.enabled
        ) {
          continue;
        }

        // Check if extension is in our conflict list
        if (this.conflictingExtensions.has(extension.id)) {
          conflicts.push({
            id: extension.id,
            name: extension.name,
            detectedAs: this.conflictingExtensions.get(extension.id),
          });
        }

        // Check for cookie-related extensions by name/description
        if (this.isLikelyConflictingExtension(extension)) {
          conflicts.push({
            id: extension.id,
            name: extension.name,
            detectedAs: "Potential Privacy/Cookie Extension",
          });
        }
      }

      return conflicts;
    } catch (error) {
      console.error("Error checking for conflicts:", error);
      return [];
    }
  }

  /**
   * Check if extension is likely conflicting based on name/description
   */
  isLikelyConflictingExtension(extension) {
    const suspiciousTerms = [
      "cookie",
      "privacy",
      "adblock",
      "adblocker",
      "ghostery",
      "tracker",
      "anti-track",
      "security",
      "cleaner",
      "vpn",
      "proxy",
      "incognito",
      "private",
      "anonymous",
      "protection",
      "blocker",
      "filter",
      "guard",
      "shield",
      "defender",
    ];

    const name = extension.name.toLowerCase();
    const description = (extension.description || "").toLowerCase();
    const shortName = (extension.shortName || "").toLowerCase();

    return suspiciousTerms.some(
      (term) =>
        name.includes(term) ||
        description.includes(term) ||
        shortName.includes(term)
    );
  }

  /**
   * Handle conflicts when detected
   */
  async handleConflicts(conflicts) {
    if (conflicts.length === 0) {
      this.isBlocked = false;
      this.violationShown = false;
      return false;
    }

    console.warn("Conflicting extensions detected:", conflicts);

    // Show violation message
    if (!this.violationShown) {
      this.showViolationAlert(conflicts);
      this.violationShown = true;
    }

    // Block our extension functionality
    this.isBlocked = true;

    // Try to disable our extension (if possible)
    try {
      await chrome.management.setEnabled(chrome.runtime.id, false);
    } catch (error) {
      console.log("Cannot disable extension directly:", error.message);
      // Extension will need to be disabled manually
    }

    // Report conflicts to backend
    await this.reportConflictsToBackend(conflicts);

    return true;
  }

  /**
   * Show violation alert to user
   */
  showViolationAlert(conflicts) {
    const conflictNames = conflicts.map((c) => c.name).join(", ");

    // Create violation popup
    const alertMessage = `
        🚫 PRIVACY POLICY VIOLATION DETECTED
  
        You have installed extensions that conflict with our privacy policy:
        ${conflictNames}
  
        These extensions interfere with SemrushToolz Ultimate's functionality.
  
        ACTION REQUIRED:
        1. Remove the conflicting extensions from Chrome
        2. Restart your browser
        3. Reinstall SemrushToolz Ultimate
  
        Your extension has been temporarily disabled for security reasons.
      `;

    // Show alert
    if (typeof alert !== "undefined") {
      alert(alertMessage);
    }

    // Also create a notification if possible
    if (chrome.notifications) {
      chrome.notifications.create("conflict-violation", {
        type: "basic",
        iconUrl: "/assets/icon48.png",
        title: "SemrushToolz Ultimate - Policy Violation",
        message: `Conflicting extensions detected: ${conflictNames}. Extension has been disabled.`,
        priority: 2,
      });
    }

    // Create popup window if possible
    try {
      chrome.windows.create({
        url: chrome.runtime.getURL("violation.html"),
        type: "popup",
        width: 500,
        height: 400,
        focused: true,
      });
    } catch (error) {
      console.log("Could not create violation popup:", error);
    }
  }

  /**
   * Report conflicts to backend
   */
  async reportConflictsToBackend(conflicts) {
    try {
      // Get stored token
      const result = await chrome.storage.local.get(["token"]);
      const token = result.token;

      if (!token) {
        console.log("No token available to report conflicts");
        return;
      }

      // Get extension ID
      const extensionId = chrome.runtime.id;

      // Report to backend
      const response = await fetch(
        "http://localhost/semrush-backend/api/extension-conflicts.php",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({
            extensionId: extensionId,
            conflicts: conflicts,
            action: "violation_detected",
            timestamp: new Date().toISOString(),
          }),
        }
      );

      if (response.ok) {
        console.log("Conflicts reported to backend successfully");
      }
    } catch (error) {
      console.error("Failed to report conflicts to backend:", error);
    }
  }

  /**
   * Start monitoring for conflicts
   */
  startMonitoring() {
    // Initial check
    this.checkForConflicts().then((conflicts) => {
      this.handleConflicts(conflicts);
    });

    // Monitor extension installations/uninstalls
    if (chrome.management && chrome.management.onInstalled) {
      chrome.management.onInstalled.addListener(async (info) => {
        console.log("Extension installed:", info.name);
        // Wait a bit for the extension to fully load
        setTimeout(async () => {
          const conflicts = await this.checkForConflicts();
          await this.handleConflicts(conflicts);
        }, 2000);
      });
    }

    if (chrome.management && chrome.management.onUninstalled) {
      chrome.management.onUninstalled.addListener(async (id) => {
        console.log("Extension uninstalled:", id);
        // Check if conflicts are resolved
        setTimeout(async () => {
          const conflicts = await this.checkForConflicts();
          if (conflicts.length === 0) {
            this.isBlocked = false;
            this.violationShown = false;
            console.log(
              "Conflicts resolved, extension can resume normal operation"
            );
          }
        }, 1000);
      });
    }

    if (chrome.management && chrome.management.onEnabled) {
      chrome.management.onEnabled.addListener(async (info) => {
        console.log("Extension enabled:", info.name);
        const conflicts = await this.checkForConflicts();
        await this.handleConflicts(conflicts);
      });
    }

    if (chrome.management && chrome.management.onDisabled) {
      chrome.management.onDisabled.addListener(async (info) => {
        console.log("Extension disabled:", info.name);
        // Check if conflicts are resolved
        const conflicts = await this.checkForConflicts();
        if (conflicts.length === 0) {
          this.isBlocked = false;
          this.violationShown = false;
        }
      });
    }

    // Periodic check every 30 seconds
    setInterval(async () => {
      if (!this.isBlocked) {
        const conflicts = await this.checkForConflicts();
        await this.handleConflicts(conflicts);
      }
    }, 30000);
  }

  /**
   * Check if extension is currently blocked
   */
  isExtensionBlocked() {
    return this.isBlocked;
  }
}

// Export for use in background script
if (typeof module !== "undefined" && module.exports) {
  module.exports = ConflictDetector;
} else if (typeof window !== "undefined") {
  window.ConflictDetector = ConflictDetector;
}
