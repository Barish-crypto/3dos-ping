const fs = require("fs");
const fsPromises = require("fs/promises");
const path = require("path");
const axios = require("axios");
const colors = require("colors");
const { HttpsProxyAgent } = require("https-proxy-agent");
const { sleep, loadData, getRandomNumber, saveJson, isTokenExpired } = require("./utils.js");
const { checkBaseUrl } = require("./checkAPI");
const user_agents = require("./config/userAgents.js");
const settings = require("./config/config.js");

let intervalIds = [];

class ClientAPI {
    constructor(itemData, accountIndex, proxies, baseURL, localStorage) {
        this.extensionId = "chrome-extension://lhmminnoafalclkgcbokfcngkocoffcp";
        this.headers = {
            Accept: "*/*",
            "Accept-Language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "none",
            Origin: "https://dashboard.3dos.io",
            Referer: "https://dashboard.3dos.io/",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
        };
        
        this.itemData = itemData;
        this.accountIndex = accountIndex;
        this.proxies = proxies; // Array of all proxies
        this.currentProxyIndex = accountIndex % proxies.length; // Initial proxy index
        this.proxy = proxies[this.currentProxyIndex];
        this.proxyIP = null;
        this.baseURL = baseURL;
        this.baseURL_v2 = settings.BASE_URL_v2;
        this.session_name = itemData.email;
        this.session_user_agents = this.#loadSessionData();
        this.token = null;
        this.authInfo = null;
        this.localStorage = localStorage;
    }

    #loadSessionData() {
        try {
            const filePath = path.join(process.cwd(), "session_user_agents.json");
            return JSON.parse(fs.readFileSync(filePath, "utf8")) || {};
        } catch (error) {
            return {};
        }
    }

    #saveSessionData(session_user_agents) {
        try {
            const filePath = path.join(process.cwd(), "session_user_agents.json");
            fs.writeFileSync(filePath, JSON.stringify(session_user_agents, null, 2));
        } catch (error) {
            this.log(`Failed to save session data: ${error.message}`, "error");
        }
    }

    #getRandomUserAgent() {
        return user_agents[Math.floor(Math.random() * user_agents.length)];
    }

    #getUserAgent() {
        if (this.session_user_agents[this.session_name]) {
            return this.session_user_agents[this.session_name];
        }

        this.log(`Creating new user agent...`);
        const newUserAgent = this.#getRandomUserAgent();
        this.session_user_agents[this.session_name] = newUserAgent;
        this.#saveSessionData(this.session_user_agents);
        return newUserAgent;
    }

    #getPlatform(userAgent) {
        const platformPatterns = [
            { pattern: /iPhone|iPad/i, platform: "ios" },
            { pattern: /Android/i, platform: "android" },
        ];

        for (const { pattern, platform } of platformPatterns) {
            if (pattern.test(userAgent)) return platform;
        }
        return "Unknown";
    }

    #setHeaders() {
        const platform = this.#getPlatform(this.#getUserAgent());
        this.headers["sec-ch-ua"] = `Not)A;Brand";v="99", "${platform} WebView";v="127", "Chromium";v="127`;
        this.headers["sec-ch-ua-platform"] = platform;
        this.headers["User-Agent"] = this.#getUserAgent();
    }

    async log(msg, type = "info") {
        const accountPrefix = `[3DOS][Account ${this.accountIndex + 1}][${this.itemData.email}]`;
        const ipPrefix = settings.USE_PROXY && this.proxyIP ? `[${this.proxyIP}]` : "[Local IP]";
        const logMessage = `${accountPrefix}${ipPrefix} ${msg}`;

        console.log({
            success: logMessage.green,
            error: logMessage.red,
            warning: logMessage.yellow,
            custom: logMessage.magenta,
            info: logMessage.blue
        }[type]);
    }

    async checkProxyIP() {
        const maxAttempts = this.proxies.length;
        let attempts = 0;

        while (attempts < maxAttempts) {
            try {
                const proxyAgent = new HttpsProxyAgent(this.proxy);
                const response = await axios.get("https://api.ipify.org?format=json", {
                    httpsAgent: proxyAgent,
                    timeout: 10000
                });

                this.proxyIP = response.data.ip;
                this.log(`Proxy IP: ${this.proxyIP}`, "success");
                return true;
            } catch (error) {
                this.log(`Proxy ${this.proxy} failed: ${error.message}`, "error");
                attempts++;
                
                // Try next proxy
                this.currentProxyIndex = (this.currentProxyIndex + 1) % this.proxies.length;
                this.proxy = this.proxies[this.currentProxyIndex];
                this.log(`Switching to proxy: ${this.proxy}`, "warning");
                
                if (attempts === maxAttempts) {
                    this.log("All proxies failed", "error");
                    return false;
                }
                await sleep(2);
            }
        }
        return false;
    }

    async makeRequest(url, method, data = {}, options = {}) {
        const { retries = 2, isAuth = false, extraHeaders = {}, refreshToken = null } = options;
        const headers = { ...this.headers, ...extraHeaders };

        if (!isAuth) {
            headers["authorization"] = `Bearer ${this.token}`;
        }

        let proxyAgent = null;
        if (settings.USE_PROXY) {
            proxyAgent = new HttpsProxyAgent(this.proxy);
        }

        let currRetries = 0;
        while (currRetries <= retries) {
            try {
                const response = await axios({
                    method,
                    url,
                    headers,
                    timeout: 120000,
                    ...(proxyAgent ? { httpsAgent: proxyAgent, httpAgent: proxyAgent } : {}),
                    ...(method.toLowerCase() !== "get" ? { data } : {}),
                });

                return {
                    status: response.status,
                    success: true,
                    data: response?.data?.data || response.data,
                    error: null
                };
            } catch (error) {
                const errorStatus = error.response?.status || 0;
                const errorMessage = error.response?.data || error.message;
                
                this.log(`Request failed: ${url} | Status: ${errorStatus} | ${JSON.stringify(errorMessage)}`, "warning");

                if (errorStatus === 401) {
                    this.log("Unauthorized, trying to get new token...");
                    this.token = await this.getValidToken(true);
                    return await this.makeRequest(url, method, data, options);
                }
                if (errorStatus === 400) {
                    this.log("Invalid request, possible server update needed", "error");
                    return { success: false, status: errorStatus, error: errorMessage, data: null };
                }
                if (errorStatus === 429) {
                    this.log("Rate limit hit, waiting 60s", "warning");
                    await sleep(60);
                }

                currRetries++;
                if (currRetries > retries) {
                    return { success: false, status: errorStatus, error: errorMessage, data: null };
                }
                await sleep(5);
            }
        }
    }

    async auth() {
        const payload = {
            email: this.itemData.email,
            password: this.itemData.password,
        };
        return this.makeRequest(`${this.baseURL}/auth/login`, "post", payload, { isAuth: true });
    }

    async getBalance() {
        return this.makeRequest(`${this.baseURL}/refresh-points/${this.itemData.api_secret}`, "get", null, {
            extraHeaders: {
                Origin: "chrome-extension://lpindahibbkakkdjifonckbhopdoaooe",
            },
        });
    }

    async getUserData() {
        return this.makeRequest(`${this.baseURL}/profile/me`, "post", {});
    }

    async genarateKeySecret() {
        return this.makeRequest(`${this.baseURL}/profile/generate-api-key`, "post", {});
    }

    async applySecret() {
        return this.makeRequest(`${this.baseURL}/profile/api/${this.itemData.api_secret}`, "post", null);
    }

    async checkin() {
        return this.makeRequest(`${this.baseURL}/claim-reward`, "post", { id: "daily-reward-api" });
    }

    async getValidToken(isNew = false) {
        const existingToken = this.token;
        const { isExpired, expirationDate } = isTokenExpired(existingToken);

        this.log(`Access token status: ${isExpired ? "Expired" : "Valid"} | Expires: ${expirationDate}`);
        if (existingToken && !isNew && !isExpired) {
            this.log("Using valid token", "success");
            return existingToken;
        }

        this.log("Getting new token...", "warning");
        const loginRes = await this.auth();
        if (!loginRes?.success) {
            this.log("Authentication failed", "error");
            return null;
        }

        const newToken = loginRes.data;
        if (newToken?.access_token) {
            await saveJson(this.session_name, JSON.stringify(newToken), "localStorage.json");
            this.log("New token acquired", "success");
            return newToken.access_token;
        }

        this.log("Failed to get new token", "error");
        return null;
    }

    async handleCheckPoint() {
        const balanceData = await this.getBalance();
        if (!balanceData.success) {
            this.log("Failed to sync points", "warning");
            return;
        }
        const total_points = balanceData.data?.total_points;
        this.log(`Total points: ${total_points} | Recheck in 5 minutes`, "custom");
    }

    async checkInvaliable(nextClaimTime) {
        const currentTime = Math.floor(Date.now() / 1000);
        const claimTime = new Date(nextClaimTime).getTime() / 1000;
        return currentTime >= claimTime;
    }

    async handleCheckin() {
        const resCheckin = await this.checkin();
        if (resCheckin.success) {
            this.log("Check-in successful", "success");
        } else {
            this.log(`Check-in failed: ${JSON.stringify(resCheckin)}`, "warning");
        }
    }

    async handleSyncData() {
        this.log("Syncing data...");
        let userData = null;
        let retries = 0;

        while (retries < 2) {
            userData = await this.getUserData();
            if (userData?.success) break;
            retries++;
            await sleep(5);
        }

        if (userData?.success) {
            const { api_secret, email_verified_at, loyalty_points, username, todays_earning, next_daily_reward_claim } = userData.data;
            
            this.log(
                `Username: ${username} | Today's earning: ${todays_earning} | Total points: ${loyalty_points} | Email verified: ${
                    email_verified_at ? new Date(email_verified_at).toLocaleDateString() : "Not verified"
                }`,
                "custom"
            );

            if (!api_secret) {
                if (!email_verified_at) {
                    this.log("Email not verified, skipping account", "warning");
                    return null;
                }
                
                this.log("Generating new secret key...", "warning");
                const result = await this.genarateKeySecret();
                if (result?.success) {
                    this.itemData.api_secret = result.data.api_secret;
                    this.log("New secret key generated", "success");
                } else {
                    this.log(`Failed to generate secret key: ${JSON.stringify(result)}`, "warning");
                }
            } else {
                this.itemData.api_secret = api_secret;
            }
            return userData;
        }
        
        this.log("Failed to sync data", "warning");
        return null;
    }

    async handleHB() {
      const result = await this.makeRequest(
          `${this.baseURL}/profile/api/${this.itemData.api_secret}`,
          "post",
          {},
          {
              extraHeaders: {
                  Origin: "chrome-extension://lpindahibbkakkdjifonckbhopdoaooe",
              },
          }
      );

      if (result?.success) {
          this.log(`[${new Date().toLocaleString()}] Ping successful`, "success");
      } else {
          this.log(`[${new Date().toLocaleString()}] Ping failed: ${JSON.stringify(result || {})}`, "warning");
      }
  }
    async runAccount() {
        this.authInfo = JSON.parse(this.localStorage[this.session_name] || "{}");
        this.token = this.authInfo?.access_token;
        this.#setHeaders();

        if (settings.USE_PROXY) {
            if (!await this.checkProxyIP()) {
                this.log("No working proxies available, skipping account", "error");
                return;
            }
            await sleep(getRandomNumber(settings.DELAY_START_BOT[0], settings.DELAY_START_BOT[1]));
        }

        const token = await this.getValidToken();
        if (!token) {
            this.log("Failed to get token, skipping account", "error");
            return;
        }
        this.token = token;

        const userData = await this.handleSyncData();
        if (!userData?.success) return;

        if (!userData.data.next_daily_reward_claim || await this.checkInvaliable(userData.data.next_daily_reward_claim)) {
            await this.handleCheckin();
        } else {
            this.log(`Already checked in today | Next: ${new Date(userData.data.next_daily_reward_claim).toLocaleString()}`, "warning");
        }

        const interValCheckPoint = setInterval(() => this.handleSyncData(), 3 * 60 * 60 * 1000);
        intervalIds.push(interValCheckPoint);

        if (settings.AUTO_MINING) {
            await this.applySecret();
            const interValHB = setInterval(() => this.handleHB(), settings.DELAY_PING * 1000);
            intervalIds.push(interValHB);
        }
    }
}

function stopInterVal() {
    intervalIds.forEach(clearInterval);
    intervalIds = [];
}

async function main() {
    console.log(colors.yellow("Tool developed by Airdrop Hunter Siêu Tốc (https://t.me/airdrophuntersieutoc)"));

    const data = loadData("data.txt");
    const proxies = loadData("proxy.txt");
    let localStorage = {};

    try {
        localStorage = JSON.parse(await fsPromises.readFile("localStorage.json", "utf8"));
    } catch (error) {
        await fsPromises.writeFile("localStorage.json", JSON.stringify({}));
    }

    if (data.length === 0) {
        console.log("No account data found".red);
        return;
    }

    if (settings.USE_PROXY && proxies.length === 0) {
        console.log("No proxies found".red);
        return;
    }

    const { endpoint, message } = await checkBaseUrl();
    if (!endpoint) {
        console.log("Failed to find API endpoint".red);
        return;
    }
    console.log(message.yellow);

    const itemDatas = data
        .map((val, index) => {
            const [email, password] = val.split("|");
            if (!email || !password) return null;
            return { email, password, index };
        })
        .filter(Boolean);

    process.on("SIGINT", async () => {
        console.log("Stopping...".yellow);
        stopInterVal();
        await sleep(1);
        process.exit(0);
    });

    const maxThreads = settings.USE_PROXY ? settings.MAX_THEADS : settings.MAX_THEADS_NO_PROXY;
    
    for (let i = 0; i < itemDatas.length; i += maxThreads) {
        const batch = itemDatas.slice(i, i + maxThreads);
        const promises = batch.map(async (itemData, indexInBatch) => {
            const accountIndex = i + indexInBatch;
            const client = new ClientAPI(itemData, accountIndex, proxies, endpoint, localStorage);
            return client.runAccount();
        });
        await Promise.all(promises);
    }
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});