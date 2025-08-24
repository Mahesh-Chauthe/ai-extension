// Popup script for enterprise extension
const chrome = window.chrome // Declare the chrome variable

class ExtensionPopup {
  constructor() {
    this.init()
  }

  async init() {
    // Show loading initially
    this.showLoading()

    // Check authentication status
    const authStatus = await chrome.runtime.sendMessage({ action: "checkAuth" })

    if (authStatus.authenticated) {
      await this.showDashboard(authStatus.user)
    } else {
      this.showLoginForm()
    }

    this.setupEventListeners()
  }

  showLoading() {
    document.getElementById("loading").style.display = "block"
    document.getElementById("loginForm").classList.remove("active")
    document.getElementById("dashboard").classList.remove("active")
  }

  showLoginForm() {
    document.getElementById("loading").style.display = "none"
    document.getElementById("loginForm").classList.add("active")
    document.getElementById("dashboard").classList.remove("active")
  }

  async showDashboard(user) {
    document.getElementById("loading").style.display = "none"
    document.getElementById("loginForm").classList.remove("active")
    document.getElementById("dashboard").classList.add("active")

    // Populate user information
    document.getElementById("userName").textContent = `${user.firstName} ${user.lastName}`
    document.getElementById("userEmail").textContent = user.email
    document.getElementById("userRole").textContent = user.role.replace("_", " ").toUpperCase()
    document.getElementById("userOrg").textContent = user.organization.name

    // Load license information
    await this.loadLicenseInfo()

    // Update status indicators
    this.updateStatusIndicators()
  }

  async loadLicenseInfo() {
    try {
      const licenseInfo = await chrome.runtime.sendMessage({ action: "getLicenseInfo" })

      if (licenseInfo) {
        document.getElementById("licenseType").textContent = licenseInfo.type.toUpperCase()
        document.getElementById("licenseSeats").textContent = `${licenseInfo.seatsUsed}/${licenseInfo.totalSeats}`

        // Update license status
        const statusElement = document.getElementById("licenseStatus")
        const statusTextElement = document.getElementById("licenseStatusText")

        statusElement.className = "status-indicator status-active"
        statusTextElement.textContent = "Active"
      } else {
        document.getElementById("licenseStatus").className = "status-indicator status-inactive"
        document.getElementById("licenseStatusText").textContent = "Invalid"
      }
    } catch (error) {
      console.error("Failed to load license info:", error)
      document.getElementById("licenseStatus").className = "status-indicator status-warning"
      document.getElementById("licenseStatusText").textContent = "Error"
    }
  }

  updateStatusIndicators() {
    // Update monitoring status
    document.getElementById("monitoringStatus").className = "status-indicator status-active"
    document.getElementById("monitoringText").textContent = "Active"

    // Update detection status
    document.getElementById("detectionStatus").className = "status-indicator status-active"
    document.getElementById("detectionText").textContent = "Enabled"
  }

  setupEventListeners() {
    // Login form
    document.getElementById("loginBtn").addEventListener("click", this.handleLogin.bind(this))

    // Dashboard actions
    document.getElementById("logoutBtn").addEventListener("click", this.handleLogout.bind(this))
    document.getElementById("analyzePageBtn").addEventListener("click", this.analyzePage.bind(this))
    document.getElementById("viewLogsBtn").addEventListener("click", this.viewLogs.bind(this))
    document.getElementById("settingsBtn").addEventListener("click", this.openSettings.bind(this))
    document
      .getElementById("helpBtn")
      .addEventListener("click", this.openHelp.bind(this))

    // Enter key support for login
    ;["organizationDomain", "email", "password"].forEach((id) => {
      document.getElementById(id).addEventListener("keypress", (e) => {
        if (e.key === "Enter") {
          this.handleLogin()
        }
      })
    })
  }

  async handleLogin() {
    const loginBtn = document.getElementById("loginBtn")
    const errorMessage = document.getElementById("errorMessage")

    // Get form data
    const organizationDomain = document.getElementById("organizationDomain").value.trim()
    const email = document.getElementById("email").value.trim()
    const password = document.getElementById("password").value

    // Validate input
    if (!email || !password) {
      this.showError("Please fill in all required fields")
      return
    }

    // Show loading state
    loginBtn.disabled = true
    loginBtn.innerHTML = '<div class="spinner"></div>Signing In...'
    errorMessage.style.display = "none"

    try {
      const result = await chrome.runtime.sendMessage({
        action: "login",
        data: {
          email,
          password,
          organizationDomain: organizationDomain || null,
        },
      })

      if (result.success) {
        await this.showDashboard(result.user)
      } else {
        this.showError(result.error || "Login failed")
      }
    } catch (error) {
      this.showError("Network error. Please try again.")
    } finally {
      loginBtn.disabled = false
      loginBtn.textContent = "Sign In"
    }
  }

  async handleLogout() {
    const logoutBtn = document.getElementById("logoutBtn")
    logoutBtn.disabled = true
    logoutBtn.textContent = "Signing Out..."

    try {
      await chrome.runtime.sendMessage({ action: "logout" })
      this.showLoginForm()

      // Clear form
      document.getElementById("organizationDomain").value = ""
      document.getElementById("email").value = ""
      document.getElementById("password").value = ""
    } catch (error) {
      console.error("Logout error:", error)
    } finally {
      logoutBtn.disabled = false
      logoutBtn.textContent = "Sign Out"
    }
  }

  async analyzePage() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })

      // Get page content
      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        function: () => {
          return {
            title: document.title,
            content: document.body.innerText.substring(0, 5000), // Limit content
            url: window.location.href,
          }
        },
      })

      if (results && results[0]) {
        const pageData = results[0].result

        // Analyze content
        const analysis = await chrome.runtime.sendMessage({
          action: "analyzeSensitiveData",
          data: {
            content: pageData.content,
            url: pageData.url,
          },
        })

        // Show results
        if (analysis.hasSensitiveData) {
          alert(
            `⚠️ Sensitive Data Detected!\n\nRisk Score: ${(analysis.riskScore * 100).toFixed(1)}%\nDetections: ${analysis.detections.length}\nAction: ${analysis.action.toUpperCase()}`,
          )
        } else {
          alert("✅ No sensitive data detected on this page.")
        }
      }
    } catch (error) {
      console.error("Page analysis error:", error)
      alert("Failed to analyze page. Please try again.")
    }
  }

  viewLogs() {
    chrome.tabs.create({
      url: "https://admin.extension-system.com/logs",
    })
  }

  openSettings() {
    chrome.runtime.openOptionsPage()
  }

  openHelp() {
    chrome.tabs.create({
      url: "https://admin.extension-system.com/help",
    })
  }

  showError(message) {
    const errorElement = document.getElementById("errorMessage")
    errorElement.textContent = message
    errorElement.style.display = "block"

    setTimeout(() => {
      errorElement.style.display = "none"
    }, 5000)
  }
}

// Initialize popup when DOM is loaded
document.addEventListener("DOMContentLoaded", () => {
  new ExtensionPopup()
})
