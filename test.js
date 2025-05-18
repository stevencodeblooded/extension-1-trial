class ConflictDetector {
  constructor() {
    this.conflictingExtensions = new Map([
      // ... your existing map ...
    ]);

    this.violationShown = false;
    this.isBlocked = false;
    this.initialized = false; // Add this flag
  }

  async checkForConflicts() {
    if (!this.initialized) {
      console.warn("ConflictDetector not fully initialized yet");
      return [];
    }

    try {
      const installedExtensions = await chrome.management.getAll();
      // ... rest of your existing code ...
    } catch (error) {
      console.error("Error checking for conflicts:", error);
      return [];
    }
  }

  async startMonitoring() {
    // Set initialized flag
    this.initialized = true;

    // ... rest of your existing startMonitoring code ...
  }
}
