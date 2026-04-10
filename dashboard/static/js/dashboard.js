class Dashboard {
    constructor() {
        this.ws = null;
        this.liveWs = null;
        this.charts = {};
        this.map = null;
        this.markers = [];
        this.refreshInterval = null;
        this.riskHistory = { labels: [], faible: [], moyen: [], critique: [] };
        this.trafficHistory = { labels: [], packets: [], bytes: [] };
        this.hybridStatus = null;
        this.hybridDetailsVisible = false;
        this.statsBuffer = {};
        this.frontendCapabilities = {
            charts: typeof Chart !== 'undefined',
            globe: typeof Globe !== 'undefined'
        };

        this.init();
    }

    init() {
        this.setupTabs();
        this.fetchHybridStatus().then(() => {
            this.initCharts();
            this.connectWebSocket();
            this.startDataRefresh();
            this.setupEventListeners();
            this.initChatbot();

            const hybridToggleBtn = document.getElementById('hybrid-toggle-details');
            if (hybridToggleBtn) {
                hybridToggleBtn.addEventListener('click', () => {
                    this.hybridDetailsVisible = !this.hybridDetailsVisible;
                    if (this.hybridStatus) {
                        this.updateHybridStatus(this.hybridStatus);
                    }
                });
            }
        });
    }

    initChatbot() {
        this.chatbotToggleBtn = document.getElementById('chatbot-toggle-btn');
        this.chatbotFloating = document.getElementById('chatbot-floating');
        this.chatbotStatus = document.getElementById('chatbot-status');
        this.chatbotMessages = document.getElementById('chatbot-messages');
        this.chatbotInput = document.getElementById('chatbot-input');
        this.chatbotSend = document.getElementById('chatbot-send');
        this.chatbotClear = document.getElementById('chatbot-clear');

        if (!this.chatbotInput) return;

        this.chatbotToggleBtn.addEventListener('click', () => this.toggleChatbot());
        this.chatbotSend.addEventListener('click', () => this.sendChatMessage());
        this.chatbotInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.sendChatMessage();
        });
        this.chatbotClear.addEventListener('click', () => this.clearConversation());

        // Load conversation from session
        this.loadConversation();

        this.checkChatbotStatus();
    }

    toggleChatbot() {
        this.chatbotFloating.classList.toggle('show');
    }

    async checkChatbotStatus() {
        const data = await this.apiFetch('/api/chatbot/status');
        this.setChatbotAvailability(data);
    }

    setChatbotAvailability(data) {
        if (!this.chatbotStatus) return;

        const enabled = Boolean(data && data.enabled);
        const mode = data?.mode || 'disabled';
        if (enabled) {
            if (mode === 'hybrid') {
                this.chatbotStatus.textContent = `Hybride (${data.model || 'cloud'})`;
            } else if (mode === 'cloud') {
                this.chatbotStatus.textContent = `Cloud (${data.model || 'LLM'})`;
            } else {
                this.chatbotStatus.textContent = 'Local';
            }
            this.chatbotStatus.className = 'chatbot-status online';
            this.chatbotStatus.title = data.reason || data.provider || mode;
            if (this.chatbotInput) {
                this.chatbotInput.disabled = false;
                this.chatbotSend.disabled = false;
                this.chatbotInput.placeholder = mode === 'local'
                    ? 'Mode local actif (cloud optionnel).'
                    : 'Posez une question en langage naturel...';
            }
            return;
        }

        const reason = data?.reason || 'Service indisponible';
        this.chatbotStatus.textContent = 'Indisponible';
        this.chatbotStatus.className = 'chatbot-status offline';
        this.chatbotStatus.title = reason;
        if (this.chatbotInput) {
            this.chatbotInput.disabled = true;
            this.chatbotSend.disabled = true;
            this.chatbotInput.placeholder = reason;
        }
    }

    async sendChatMessage() {
        const message = this.chatbotInput.value.trim();
        if (!message) return;

        const userMessageDiv = this.addChatMessage(message, 'user');
        this.chatbotInput.value = '';

        this.addTypingIndicator();

        try {
            // Add timeout to fetch
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 60000); // 60s timeout (moins de false timeout)

            const resp = await fetch('/api/chatbot/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `message=${encodeURIComponent(message)}`,
                signal: controller.signal
            });
            clearTimeout(timeoutId);

            const data = await resp.json();

            this.removeTypingIndicator();
            this.addChatMessage(data.response, data.type || 'bot');
        } catch (e) {
            this.removeTypingIndicator();
            if (e.name === 'AbortError') {
                // Timeout occurred
                const timeoutDiv = this.addChatMessage('Timeout - réponse trop lente. Cliquez sur 🔄 pour réessayer.', 'error');
                // Add styled resend button to timeout message
                const resendBtn = document.createElement('button');
                resendBtn.className = 'chatbot-message-action-btn';
                resendBtn.textContent = '🔄 Renvoyer';
                resendBtn.title = 'Renvoyer le message';
                resendBtn.style.marginLeft = '8px';
                resendBtn.style.background = 'var(--accent-red)';
                resendBtn.style.color = 'white';
                resendBtn.addEventListener('click', () => this.resendMessage(message));
                timeoutDiv.appendChild(resendBtn);
            } else {
                this.addChatMessage('Erreur de connexion', 'error');
            }
        }
    }

    addChatMessage(text, type, save = true, timestamp = null) {
        const div = document.createElement('div');
        div.className = `chatbot-message ${type}`;

        const textDiv = document.createElement('div');
        textDiv.className = 'chatbot-message-text';
        textDiv.textContent = text;
        div.appendChild(textDiv);

        const timeDiv = document.createElement('div');
        timeDiv.className = 'chatbot-message-timestamp';
        const time = timestamp || Date.now();
        timeDiv.textContent = new Date(time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        div.appendChild(timeDiv);

        if (type === 'user') {
            const actionsDiv = document.createElement('div');
            actionsDiv.className = 'chatbot-message-actions';

            const editBtn = document.createElement('button');
            editBtn.className = 'chatbot-message-action-btn';
            editBtn.textContent = 'Éditer';
            editBtn.title = 'Modifier le message';
            editBtn.addEventListener('click', () => this.editMessage(div, text));

            const resendBtn = document.createElement('button');
            resendBtn.className = 'chatbot-message-action-btn';
            resendBtn.textContent = 'Renvoyer';
            resendBtn.title = 'Renvoyer le message';
            resendBtn.addEventListener('click', () => this.resendMessage(text));

            const copyBtn = document.createElement('button');
            copyBtn.className = 'chatbot-message-action-btn';
            copyBtn.textContent = 'Copier';
            copyBtn.title = 'Copier le message';
            copyBtn.addEventListener('click', () => this.copyMessage(text));

            actionsDiv.appendChild(editBtn);
            actionsDiv.appendChild(resendBtn);
            actionsDiv.appendChild(copyBtn);
            div.appendChild(actionsDiv);
        }

        this.chatbotMessages.appendChild(div);
        this.chatbotMessages.scrollTop = this.chatbotMessages.scrollHeight;

        // Save to session
        if (save) {
            this.saveMessageToSession({ text, type, timestamp: Date.now() });
        }

        return div;
    }

    saveMessageToSession(message) {
        const conversation = this.getConversation();
        conversation.push(message);
        localStorage.setItem('chatbot_conversation', JSON.stringify(conversation));
    }

    getConversation() {
        const stored = localStorage.getItem('chatbot_conversation');
        return stored ? JSON.parse(stored) : [];
    }

    loadConversation() {
        this.chatbotMessages.innerHTML = '';
        const conversation = this.getConversation();
        conversation.forEach(msg => {
            this.addChatMessage(msg.text, msg.type, false, msg.timestamp);
        });
    }

    clearConversation() {
        localStorage.removeItem('chatbot_conversation');
        this.chatbotMessages.innerHTML = '';
    }

    editMessage(messageDiv, currentText) {
        const textDiv = messageDiv.querySelector('div:last-child');
        const input = document.createElement('input');
        input.type = 'text';
        input.value = currentText;
        input.className = 'chatbot-edit-input';
        input.style.width = '100%';
        input.style.border = 'none';
        input.style.background = 'transparent';
        input.style.color = 'inherit';
        input.style.fontSize = 'inherit';
        
        textDiv.replaceWith(input);
        input.focus();
        input.select();
        
        const saveEdit = () => {
            const newText = input.value.trim();
            if (newText && newText !== currentText) {
                textDiv.textContent = newText;
                input.replaceWith(textDiv);
                // Optionally resend with new text
                this.resendMessage(newText);
            } else {
                input.replaceWith(textDiv);
            }
        };
        
        input.addEventListener('blur', saveEdit);
        input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') saveEdit();
            if (e.key === 'Escape') input.replaceWith(textDiv);
        });
    }

    resendMessage(message) {
        this.chatbotInput.value = message;
        this.sendChatMessage();
    }

    copyMessage(text) {
        navigator.clipboard.writeText(text).then(() => {
            // Optional: show feedback
            console.log('Message copié');
        });
    }

    addTypingIndicator() {
        const div = document.createElement('div');
        div.className = 'chatbot-typing';
        div.id = 'chatbot-typing';
        div.innerHTML = '<span></span><span></span><span></span>';
        this.chatbotMessages.appendChild(div);
        this.chatbotMessages.scrollTop = this.chatbotMessages.scrollHeight;
    }

    removeTypingIndicator() {
        const el = document.getElementById('chatbot-typing');
        if (el) el.remove();
    }

    setupTabs() {
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(tc => tc.classList.remove('active'));
                tab.classList.add('active');
                const target = tab.dataset.tab;
                document.getElementById(`tab-${target}`).classList.add('active');
                if (target === 'map') {
                    if (!this.globe) {
                        setTimeout(() => this.initMap(), 100);
                    } else {
                        setTimeout(() => this.resizeGlobeViewport(), 100);
                    }
                }
                if (target === 'whitelist') {
                    this.fetchWhitelist();
                }
            });
        });
    }

    initCharts() {
        if (!this.frontendCapabilities.charts) {
            document.querySelectorAll('.chart-card').forEach(card => {
                const canvas = card.querySelector('canvas');
                if (!canvas) return;
                canvas.style.display = 'flex';
                canvas.style.alignItems = 'center';
                canvas.style.justifyContent = 'center';
                canvas.style.color = '#9ca3af';
                canvas.style.background = 'rgba(30,41,59,0.5)';
                canvas.style.borderRadius = '8px';
                canvas.style.minHeight = '250px';
                canvas.innerHTML = 'Graphique indisponible';
            });
            return;
        }

        const chartDefaults = {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { labels: { color: '#9ca3af', font: { size: 11 } } }
            },
            scales: {
                x: { ticks: { color: '#9ca3af', font: { size: 10 } }, grid: { color: 'rgba(55,65,81,0.3)' } },
                y: { ticks: { color: '#9ca3af', font: { size: 10 } }, grid: { color: 'rgba(55,65,81,0.3)' } }
            }
        };

        this.charts.risk = new Chart(document.getElementById('riskChart'), {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    { label: 'Faible', data: [], borderColor: '#10b981', backgroundColor: 'rgba(16,185,129,0.1)', fill: true, tension: 0.4 },
                    { label: 'Moyen', data: [], borderColor: '#f59e0b', backgroundColor: 'rgba(245,158,11,0.1)', fill: true, tension: 0.4 },
                    { label: 'Critique', data: [], borderColor: '#ef4444', backgroundColor: 'rgba(239,68,68,0.1)', fill: true, tension: 0.4 }
                ]
            },
            options: { ...chartDefaults }
        });

        this.charts.alerts = new Chart(document.getElementById('alertsChart'), {
            type: 'doughnut',
            data: {
                labels: ['Faible', 'Moyen', 'Critique'],
                datasets: [{ data: [0, 0, 0], backgroundColor: ['#10b981', '#f59e0b', '#ef4444'], borderWidth: 0 }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { labels: { color: '#9ca3af' } } }
            }
        });

        this.charts.traffic = new Chart(document.getElementById('trafficChart'), {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    { label: 'Paquets', data: [], borderColor: '#3b82f6', tension: 0.4, yAxisID: 'y' },
                    { label: 'Octets (KB)', data: [], borderColor: '#8b5cf6', tension: 0.4, yAxisID: 'y1' }
                ]
            },
            options: {
                ...chartDefaults,
                scales: {
                    ...chartDefaults.scales,
                    y1: { position: 'right', ticks: { color: '#9ca3af' }, grid: { display: false } }
                }
            }
        });

        this.charts.topIps = new Chart(document.getElementById('topIpsChart'), {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{ label: 'Score de risque', data: [], backgroundColor: [] }]
            },
            options: {
                ...chartDefaults,
                indexAxis: 'y',
                scales: {
                    x: { ticks: { color: '#9ca3af' }, grid: { color: 'rgba(55,65,81,0.3)' }, max: 1 },
                    y: { ticks: { color: '#9ca3af', font: { family: 'monospace', size: 10 } }, grid: { display: false } }
                }
            }
        });
    }

    renderStaticFallback(canvas) {
        const container = document.createElement('div');
        container.className = 'chart-fallback-static';
        
        const chartId = canvas.id || 'chart-' + Math.random().toString(36).substr(2, 9);
        
        const statMapping = {
            'riskChart': { label: 'Paquets', key: 'packets' },
            'alertsChart': { label: 'Incidents', key: 'incidents' },
            'trafficChart': { label: 'Trafic', key: 'pps' },
            'topIpsChart': { label: 'Bloquees', key: 'blocked' }
        };
        
        const mapping = statMapping[chartId];
        
        container.innerHTML = `
            <div class="chart-static-header">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                    <path d="M3 3v18h18"/><path d="M18 9l-5 5-4-4-3 3"/>
                </svg>
                <span>${mapping ? mapping.label : 'Stat'}</span>
            </div>
            <div class="chart-static-value" id="fallback-${mapping ? mapping.key : 'default'}">0</div>
            <div class="chart-static-label">Temps reel</div>
        `;
        
        canvas.replaceWith(container);
    }

    renderLineChartFallback(canvas) {
        const chartId = canvas.id || 'fallback-line-' + Math.random().toString(36).substr(2, 9);
        
        const statMapping = {
            'riskChart': { label: 'Paquets', key: 'packets_analyzed', color: '#10b981' },
            'alertsChart': { label: 'Incidents', key: 'incidents_detected', color: '#f59e0b' },
            'trafficChart': { label: 'PPS', key: 'pps', color: '#3b82f6' },
            'topIpsChart': { label: 'Bloquees', key: 'ips_blocked', color: '#ef4444' }
        };
        
        const mapping = statMapping[chartId] || { label: 'Valeur', key: 'packets_analyzed', color: '#f59e0b' };
        
        const container = document.createElement('div');
        container.className = 'line-chart-fallback';
        container.innerHTML = `
            <div class="line-chart-header">
                <span class="line-chart-title">${mapping.label}</span>
                <span class="line-chart-mode">Hors connexion</span>
            </div>
            <canvas id="line-${chartId}" width="400" height="200"></canvas>
        `;
        
        canvas.replaceWith(container);
        
        this.initLineChartFallback('line-' + chartId, mapping);
    }
    
    initLineChartFallback(canvasId, mapping) {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;
        
        canvas.width = canvas.offsetWidth || 400;
        canvas.height = 200;
        
        const ctx = canvas.getContext('2d');
        const width = canvas.width;
        const height = canvas.height;
        
        if (!this.fallbackCharts) this.fallbackCharts = {};
        if (!this.fallbackCharts[mapping.key]) this.fallbackCharts[mapping.key] = { data: [], draw: null };
        
        const chartData = this.fallbackCharts[mapping.key];
        const maxPoints = 25;
        
        const draw = () => {
            ctx.fillStyle = 'rgba(30, 41, 59, 0.95)';
            ctx.fillRect(0, 0, width, height);
            
            ctx.strokeStyle = 'rgba(55, 65, 81, 0.4)';
            ctx.lineWidth = 1;
            for (let i = 0; i <= 5; i++) {
                const y = (height / 5) * i;
                ctx.beginPath();
                ctx.moveTo(0, y);
                ctx.lineTo(width, y);
                ctx.stroke();
            }
            
            if (chartData.data.length < 2) {
                ctx.fillStyle = '#9ca3af';
                ctx.font = '14px sans-serif';
                ctx.textAlign = 'center';
                ctx.fillText('En attente de donnees...', width / 2, height / 2);
                return;
            }
            
            const maxVal = Math.max(...chartData.data, 1);
            const padding = 30;
            const chartWidth = width - padding * 2;
            const chartHeight = height - padding * 2;
            const stepX = chartWidth / (maxPoints - 1);
            
            ctx.strokeStyle = mapping.color;
            ctx.lineWidth = 2.5;
            ctx.beginPath();
            chartData.data.forEach((val, i) => {
                const x = padding + i * stepX;
                const y = height - padding - (val / maxVal) * chartHeight;
                if (i === 0) ctx.moveTo(x, y);
                else ctx.lineTo(x, y);
            });
            ctx.stroke();
            
            const gradient = ctx.createLinearGradient(0, 0, 0, height);
            gradient.addColorStop(0, mapping.color + '40');
            gradient.addColorStop(1, mapping.color + '00');
            ctx.fillStyle = gradient;
            ctx.beginPath();
            ctx.moveTo(padding, height - padding);
            chartData.data.forEach((val, i) => {
                const x = padding + i * stepX;
                const y = height - padding - (val / maxVal) * chartHeight;
                ctx.lineTo(x, y);
            });
            ctx.lineTo(padding + (chartData.data.length - 1) * stepX, height - padding);
            ctx.closePath();
            ctx.fill();
            
            ctx.fillStyle = mapping.color;
            chartData.data.forEach((val, i) => {
                const x = padding + i * stepX;
                const y = height - padding - (val / maxVal) * chartHeight;
                ctx.beginPath();
                ctx.arc(x, y, 4, 0, Math.PI * 2);
                ctx.fill();
            });
            
            if (chartData.data.length > 0) {
                const lastVal = chartData.data[chartData.data.length - 1];
                ctx.fillStyle = mapping.color;
                ctx.font = 'bold 16px monospace';
                ctx.textAlign = 'right';
                ctx.fillText(this.formatNumber(lastVal), width - 10, 25);
            }
        };
        
        chartData.draw = draw;
        draw();
        
        if (this.lastStats && this.lastStats[mapping.key] !== undefined) {
            chartData.data = [this.lastStats[mapping.key]];
            draw();
        }
    }

    renderFallbackChart(canvas, chartType = 'line') {
        const container = document.createElement('div');
        container.className = 'chart-fallback';
        container.style.position = 'relative';
        
        const originalId = canvas.id || 'fallback-chart-' + Math.random().toString(36).substr(2, 9);
        canvas.id = originalId;
        
        container.innerHTML = `
            <div class="chart-fallback-header">
                <span class="chart-fallback-icon">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                        <path d="M3 3v18h18"/><path d="M18 9l-5 5-4-4-3 3"/>
                    </svg>
                </span>
                <span class="chart-fallback-mode">Mode hors connexion</span>
            </div>
        `;
        
        canvas.style.display = 'block';
        container.appendChild(canvas);
        const parent = canvas.parentNode;
        parent.replaceChild(container, canvas);
        
        this.initFallbackChart(originalId, chartType);
    }
    
    initFallbackChart(canvasId, chartType) {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;
        
        canvas.width = canvas.offsetWidth || 300;
        canvas.height = 180;
        
        const ctx = canvas.getContext('2d');
        const width = canvas.width;
        const height = canvas.height;
        
        const history = { data: [] };
        const maxPoints = 20;
        const color = '#f59e0b';
        
        const draw = () => {
            ctx.fillStyle = 'rgba(30, 41, 59, 0.3)';
            ctx.fillRect(0, 0, width, height);
            
            ctx.strokeStyle = 'rgba(55, 65, 81, 0.5)';
            ctx.lineWidth = 1;
            for (let i = 0; i <= 4; i++) {
                const y = (height / 4) * i;
                ctx.beginPath();
                ctx.moveTo(0, y);
                ctx.lineTo(width, y);
                ctx.stroke();
            }
            
            if (history.data.length < 2) {
                ctx.fillStyle = '#9ca3af';
                ctx.font = '12px sans-serif';
                ctx.textAlign = 'center';
                ctx.fillText('En attente de donnees...', width / 2, height / 2);
                return;
            }
            
            const maxVal = Math.max(...history.data, 1);
            const stepX = width / (maxPoints - 1);
            
            ctx.strokeStyle = color;
            ctx.lineWidth = 2;
            ctx.beginPath();
            history.data.forEach((val, i) => {
                const x = i * stepX;
                const y = height - (val / maxVal) * (height - 20);
                if (i === 0) ctx.moveTo(x, y);
                else ctx.lineTo(x, y);
            });
            ctx.stroke();
            
            ctx.fillStyle = color;
            history.data.forEach((val, i) => {
                const x = i * stepX;
                const y = height - (val / maxVal) * (height - 20);
                ctx.beginPath();
                ctx.arc(x, y, 3, 0, Math.PI * 2);
                ctx.fill();
            });
            
            if (history.data.length > 0) {
                const lastVal = history.data[history.data.length - 1];
                ctx.fillStyle = '#f59e0b';
                ctx.font = 'bold 14px monospace';
                ctx.textAlign = 'right';
                ctx.fillText(this.formatNumber(lastVal), width - 10, 20);
            }
        };
        
        draw();
        
        const statsMap = {
            'riskChart': { key: 'packets_analyzed', prop: 'riskHistory' },
            'alertsChart': { key: 'incidents_detected', prop: 'alertsHistory' },
            'trafficChart': { key: 'packets_analyzed', prop: 'trafficHistory' },
            'topIpsChart': { key: 'ips_blocked', prop: 'ipBlockHistory' }
        };
        
        const mapping = statsMap[canvasId];
        if (!mapping) return;
        
        const originalUpdate = this.updateStatsFromWS.bind(this);
        this.updateStatsFromWS = (stats) => {
            originalUpdate(stats);
            
            if (stats[mapping.key] !== undefined) {
                const hist = this[mapping.prop] = this[mapping.prop] || { data: [] };
                hist.data.push(stats[mapping.key]);
                if (hist.data.length > maxPoints) {
                    hist.data.shift();
                }
                draw();
            }
        };
        
        if (this.statsBuffer && this.statsBuffer[mapping.key] !== undefined) {
            history.data = this.statsBuffer[mapping.prop] || [];
        }
    }

    initMap() {
        const container = document.getElementById('threat-map');
        if (!container || container.offsetHeight === 0) {
            setTimeout(() => this.initMap(), 200);
            return;
        }

        if (!this.frontendCapabilities.globe || typeof Globe === 'undefined') {
            container.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:#ef4444;font-size:1.1rem">Globe.gl non charge. Verifiez votre connexion internet.</div>';
            return;
        }

        try {
            // Legend
            const legend = document.createElement('div');
            legend.className = 'globe-legend';
            legend.innerHTML = `
                <div class="globe-legend-title">Niveau de risque</div>
                <div class="globe-legend-item"><span class="globe-legend-dot" style="background:#ef4444"></span> Critique</div>
                <div class="globe-legend-item"><span class="globe-legend-dot" style="background:#eab308"></span> Moyen</div>
                <div class="globe-legend-item"><span class="globe-legend-dot" style="background:#10b981"></span> Faible</div>
                <div class="globe-legend-sep"></div>
                <div class="globe-legend-item"><span class="globe-legend-dot" style="background:#3b82f6;box-shadow:0 0 6px #3b82f6"></span> Externe</div>
                <div class="globe-legend-item"><span class="globe-legend-dot" style="background:#a855f7;box-shadow:0 0 6px #a855f7"></span> Local</div>
                <div class="globe-legend-sep"></div>
                <div class="globe-legend-item"><span class="globe-legend-line"></span> Flux</div>
            `;
            container.appendChild(legend);

            // Stats overlay
            const statsOverlay = document.createElement('div');
            statsOverlay.className = 'globe-stats';
            statsOverlay.id = 'globe-stats';
            container.appendChild(statsOverlay);

            const notice = document.createElement('div');
            notice.className = 'globe-notice hidden';
            notice.id = 'globe-notice';
            container.appendChild(notice);

            const globe = Globe()
                .globeImageUrl('https://unpkg.com/three-globe/example/img/earth-blue-marble.jpg')
                .backgroundImageUrl('https://unpkg.com/three-globe/example/img/night-sky.png')
                .pointsData([])
            .pointAltitude(0.12)
            .pointRadius(d => {
                if (d.source_type === 'local') return 1.5;
                if (d.risk_level === 'critique') return 1.2;
                if (d.risk_level === 'moyen') return 1.0;
                return 0.8;
            })
                .pointColor(d => {
                    if (d.source_type === 'local') return '#a855f7';
                    if (d.risk_level === 'critique') return '#ef4444';
                    if (d.risk_level === 'moyen') return '#eab308';
                    return '#10b981';
                })
                .pointLabel(d => {
                    const loc = [d.city, d.country].filter(Boolean).join(', ');
                    const color = d.risk_level === 'critique' ? '#ef4444' : d.risk_level === 'moyen' ? '#eab308' : '#10b981';
                    const srcBadge = d.source_type === 'local'
                        ? '<span style="color:#a855f7">LOCAL</span>'
                        : '<span style="color:#3b82f6">EXTERNE</span>';
                    const continent = d.continent ? `<span style="color:#a855f7;font-weight:600">${d.continent}</span>` : '';
                    return `<div style="background:rgba(0,0,0,0.88);padding:10px 14px;border-radius:8px;color:#fff;font-size:13px;min-width:160px">
                        <strong>${d.ip}</strong> ${srcBadge}<br>
                        <span style="color:${color}">Risque: ${d.risk_level?.toUpperCase()} (${(d.risk_score || 0).toFixed(2)})</span><br>
                        <span style="color:#9ca3af">${loc || 'Inconnu'}</span><br>
                        ${continent}<br>
                        <span style="color:#6b7280;font-size:11px">${d.isp || ''}</span>
                    </div>`;
                })
                .arcsData([])
                .arcStartLat(d => d.src_lat)
                .arcStartLng(d => d.src_lon)
                .arcEndLat(d => d.dst_lat)
                .arcEndLng(d => d.dst_lon)
                .arcColor(d => {
                    if (d.risk_level === 'critique') return ['rgba(239,68,68,0.8)', 'rgba(239,68,68,0.2)'];
                    if (d.risk_level === 'moyen') return ['rgba(234,179,8,0.7)', 'rgba(234,179,8,0.15)'];
                    return ['rgba(16,185,129,0.6)', 'rgba(16,185,129,0.1)'];
                })
                .arcDashLength(0.6)
                .arcDashGap(0.15)
                .arcDashInitialGap(() => Math.random())
                .arcDashAnimateTime(2500)
                .arcAltitude(0.5)
                .arcStroke(d => d.risk_level === 'critique' ? 4.0 : 2.5)
                .arcLabel(d => {
                    const color = d.risk_level === 'critique' ? '#ef4444' : d.risk_level === 'moyen' ? '#eab308' : '#10b981';
                    const loc = [d.city, d.country].filter(Boolean).join(', ');
                    return `<div style="background:rgba(0,0,0,0.88);padding:10px 14px;border-radius:8px;color:#fff;font-size:13px;min-width:180px">
                        <strong>${d.ip}</strong><br>
                        <span style="color:${color}">Risque: ${d.risk_level?.toUpperCase()}</span><br>
                        <span style="color:#e2e8f0">${loc || 'Inconnu'}</span><br>
                        <span style="color:#a855f7;font-weight:600">${d.continent || 'Inconnu'}</span>
                    </div>`;
                })
                .ringsData([])
                .ringMaxRadius(2.5)
                .ringPropagationSpeed(2)
                .ringRepeatPeriod(1500)
                .ringColor(() => 'rgba(168,85,247,0.4)')
                .atmosphereColor('#3a228a')
                .atmosphereAltitude(0.25)
                (container);

            globe.controls().autoRotate = true;
            globe.controls().autoRotateSpeed = 0.5;
            this.globe = globe;
            this.resizeGlobeViewport();

            container.addEventListener('mouseenter', () => {
                globe.controls().autoRotate = false;
            });
            container.addEventListener('mouseleave', () => {
                globe.controls().autoRotate = true;
            });

            this._animateCriticalPulse();
            this.fetchGeoThreats();
            this._geoInterval = setInterval(() => this.fetchGeoThreats(), 15000);
        } catch (e) {
            console.error('Globe init error:', e);
            container.innerHTML = `<div style="display:flex;align-items:center;justify-content:center;height:100%;color:#ef4444;font-size:1rem;padding:2rem;text-align:center">Erreur globe: ${e.message}<br>Verifiez la console (F12) pour plus de details.</div>`;
        }
    }

    resizeGlobeViewport() {
        if (!this.globe) return;
        const container = document.getElementById('threat-map');
        if (!container) return;

        const rect = container.getBoundingClientRect();
        const width = Math.max(320, Math.floor(rect.width));
        const height = Math.max(260, Math.floor(rect.height));
        this.globe.width(width).height(height);

        const mobile = window.innerWidth <= 768;
        this.globe.pointOfView(
            { lat: 7.5, lng: -5.5, altitude: mobile ? 2.0 : 1.75 },
            0
        );
    }

    setMapNotice(message) {
        const notice = document.getElementById('globe-notice');
        if (!notice) return;
        if (!message) {
            notice.classList.add('hidden');
            notice.textContent = '';
            return;
        }
        notice.textContent = message;
        notice.classList.remove('hidden');
    }

    _animateCriticalPulse() {
        if (!this.globe) return;
        const animate = () => {
            if (!this.globe) return;
            const t = Date.now() * 0.004;
            const data = this.globe.pointsData();
            if (data && data.length) {
                this.globe.pointAltitude(d => {
                    if (d.risk_level === 'critique') {
                        return 0.12 + Math.abs(Math.sin(t)) * 0.25;
                    }
                    return 0.12;
                });
                this.globe.pointRadius(d => {
                    if (d.source_type === 'local') return 1.5;
                    if (d.risk_level === 'critique') {
                        return 1.0 + Math.abs(Math.sin(t)) * 0.6;
                    }
                    if (d.risk_level === 'moyen') return 1.0;
                    return 0.8;
                });
            }
            requestAnimationFrame(animate);
        };
        animate();
    }

    async fetchGeoThreats() {
        const resp = await this.apiFetch('/api/geo-threats');
        if (!resp || !this.globe) return;

        // Compat: API peut retourner un tableau (ancien) ou un objet (nouveau)
        let threats, local;
        if (Array.isArray(resp)) {
            threats = resp;
            local = { lat: 48.8566, lon: 2.3522, ip: '127.0.0.1' };
        } else {
            threats = resp.threats || [];
            local = resp.local || { lat: 48.8566, lon: 2.3522, ip: '127.0.0.1' };
        }
        this.setMapNotice(resp.degraded ? (resp.reason || 'Geolocalisation suspendue en mode hors connexion.') : '');

        // Points: threats + local node
        const points = [
            ...threats,
            {
                ip: local.ip,
                lat: local.lat,
                lon: local.lon,
                city: 'Vous',
                country: '',
                risk_level: 'local',
                risk_score: 0,
                source_type: 'local',
            }
        ];
        this.globe.pointsData(points);

        // Arcs: from each external threat to local node
        const arcs = threats.map(t => ({
            src_lat: t.lat,
            src_lon: t.lon,
            dst_lat: local.lat,
            dst_lon: local.lon,
            risk_level: t.risk_level,
            ip: t.ip,
            country: t.country,
            continent: t.continent,
            city: t.city,
        }));
        this.globe.arcsData(arcs);

        // Ring pulsing on local node
        this.globe.ringsData([{
            lat: local.lat,
            lng: local.lon,
        }]);

        // Stats overlay
        const counts = { critique: 0, moyen: 0, faible: 0 };
        threats.forEach(t => {
            if (counts.hasOwnProperty(t.risk_level)) counts[t.risk_level]++;
        });
        const statsEl = document.getElementById('globe-stats');
        if (statsEl) {
            statsEl.innerHTML = `
                <span class="globe-stat" style="color:#ef4444">${counts.critique} critique${counts.critique > 1 ? 's' : ''}</span>
                <span class="globe-stat" style="color:#eab308">${counts.moyen} moyen${counts.moyen > 1 ? 's' : ''}</span>
                <span class="globe-stat" style="color:#10b981">${counts.faible} faible${counts.faible > 1 ? 's' : ''}</span>
                <span class="globe-stat" style="color:#9ca3af">${threats.length} source${threats.length > 1 ? 's' : ''}</span>
            `;
        }
    }

    async fetchHybridStatus() {
        const status = await this.apiFetch('/api/hybrid/status');
        if (!status) return;
        this.hybridStatus = status;
        this.updateHybridStatus(status);
        this.checkChatbotStatus();
    }

    updateHybridStatus(status) {
        const panel = document.getElementById('hybrid-panel');
        const badge = document.getElementById('hybrid-mode-badge');
        const text = document.getElementById('hybrid-status-text');
        const services = document.getElementById('hybrid-services');
        const toggleBtn = document.getElementById('hybrid-toggle-details');
        
        const isOffline = status.online === false;

        if (panel) {
            panel.classList.toggle('hidden', !isOffline);
        }

        if (badge) {
            badge.className = isOffline ? 'hybrid-mode-badge offline' : 'hybrid-mode-badge online';
            badge.textContent = isOffline ? 'Mode hors connexion' : 'Mode connecte';
        }

        if (text) {
            const queueCount = this.formatNumber(status.queue?.pending_total || 0);
            const lastCheckText = status.last_check ? this.formatDate(status.last_check) : 'non disponible';
            if (isOffline) {
                text.textContent = `Services externes suspendus automatiquement. Dernier check: ${lastCheckText}. Sync differee: ${queueCount}.`;
            } else {
                text.textContent = `Tous les services operationnels. Dernier check: ${lastCheckText}.`;
            }
        }

        if (!isOffline) {
            this.hybridDetailsVisible = false;
            if (services) {
                services.classList.add('hidden');
                services.innerHTML = '';
            }
            if (toggleBtn) {
                toggleBtn.textContent = 'Details';
            }
            return;
        }

        if (toggleBtn) {
            toggleBtn.textContent = this.hybridDetailsVisible ? 'Masquer details' : 'Details';
        }

        if (services) {
            services.classList.toggle('hidden', !this.hybridDetailsVisible);
            if (!this.hybridDetailsVisible) {
                services.innerHTML = '';
                return;
            }

            const backendServices = Object.values(status.services || {})
                .filter(service => service.requires_internet);

            services.innerHTML = backendServices.map(service => `
                <div class="hybrid-service-chip ${service.effective_enabled ? 'online' : 'offline'}">
                    <span class="hybrid-service-state"></span>
                    <div class="hybrid-service-copy">
                        <strong>${service.label}</strong>
                        <span>${service.reason || ''}</span>
                    </div>
                </div>
            `).join('');
        }
    }

    connectWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws`;

        this.ws = new WebSocket(wsUrl);
        this.ws.onopen = () => {
            this.updateConnectionStatus(true);
        };
        this.ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                this.handleAlert(data);
            } catch (e) {}
        };
        this.ws.onclose = () => {
            this.updateConnectionStatus(false);
            setTimeout(() => this.connectWebSocket(), 5000);
        };
        this.ws.onerror = () => {
            this.updateConnectionStatus(false);
        };

        const liveUrl = `${protocol}//${window.location.host}/ws/live`;
        this.liveWs = new WebSocket(liveUrl);
        this.liveWs.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                if (data.type === 'live_update') {
                    this.updateStatsFromWS(data.stats);
                }
            } catch (e) {}
        };
    }

    updateConnectionStatus(connected) {
        const dot = document.getElementById('connection-status');
        const text = document.getElementById('connection-text');
        
        const isOffline = this.hybridStatus && this.hybridStatus.online === false;
        
        if (isOffline) {
            dot.className = 'status-dot offline';
            text.textContent = 'Hors connexion';
        } else if (connected) {
            dot.className = 'status-dot online';
            text.textContent = 'Connecte';
        } else {
            dot.className = 'status-dot offline';
            text.textContent = 'Deconnecte';
        }
    }

    updateStatsFromWS(stats) {
        if (!stats) return;
        document.getElementById('packets-count').textContent = this.formatNumber(stats.packets_analyzed || 0);
        document.getElementById('incidents-count').textContent = this.formatNumber(stats.incidents_detected || 0);
        document.getElementById('blocked-count').textContent = this.formatNumber(stats.ips_blocked || 0);
        document.getElementById('alerts-count').textContent = this.formatNumber(stats.alerts_sent || 0);
        document.getElementById('pps-value').textContent = this.formatNumber(stats.sniffer?.packets_per_second || 0);
        document.getElementById('fp-count').textContent = this.formatNumber(stats.fp_stats?.total_false_positives || 0);
        document.getElementById('whitelist-count').textContent = this.formatNumber(stats.whitelist_count || 0);
        if (stats.uptime_seconds) {
            document.getElementById('uptime-value').textContent = this.formatUptime(stats.uptime_seconds);
        }
        
        this.lastStats = stats;
    }

    startDataRefresh() {
        this.fetchHybridStatus();
        this.fetchStats();
        this.fetchIncidents();
        this.fetchBlocked();
        this.fetchTraffic();
        this.fetchAlerts();
        this.fetchLogs();
        this.fetchFalsePositives();
        this.fetchWhitelist();

        this.refreshInterval = setInterval(() => {
            this.fetchHybridStatus();
            this.fetchStats();
            this.fetchIncidents();
            this.fetchBlocked();
            this.fetchTraffic();
            this.fetchAlerts();
            this.fetchWhitelist();
        }, 5000);
    }

    async apiFetch(url, options = {}) {
        try {
            const resp = await fetch(url, options);
            if (resp.status === 401) {
                window.location.href = '/login';
                return null;
            }
            return await resp.json();
        } catch (e) {
            return null;
        }
    }

    async fetchStats() {
        const stats = await this.apiFetch('/api/stats');
        if (!stats) return;
        this.updateStatsFromWS(stats);
    }

    async fetchIncidents() {
        const level = document.getElementById('filter-level')?.value || '';
        const ip = document.getElementById('filter-ip')?.value || '';
        let url = '/api/incidents?limit=100';
        if (level) url += `&risk_level=${level}`;
        if (ip) url += `&ip=${ip}`;

        const incidents = await this.apiFetch(url);
        if (!incidents) return;

        this.renderIncidentsTable(incidents);
        this.updateChartsFromIncidents(incidents);
    }

    async fetchBlocked() {
        const blocked = await this.apiFetch('/api/blocked-ips');
        if (!blocked) return;
        this.renderBlockedTable(blocked);
    }

    async fetchTraffic() {
        const traffic = await this.apiFetch('/api/traffic');
        if (!traffic) return;
        this.renderTrafficTable(traffic);
        this.updateTrafficChart(traffic);
    }

    async fetchAlerts() {
        const alerts = await this.apiFetch('/api/alerts?limit=20');
        if (!alerts) return;
        this.renderAlertsList(alerts);
    }

    async fetchLogs(severity, ip) {
        let url = '/api/logs?count=200';
        if (severity) url += `&severity=${severity}`;
        if (ip) url += `&ip=${ip}`;
        const logs = await this.apiFetch(url);
        if (!logs) return;
        this.renderLogs(logs);
    }

    renderIncidentsTable(incidents) {
        const tbody = document.getElementById('incidents-body');
        if (!tbody) return;
        tbody.innerHTML = incidents.map(inc => {
            const isFP = inc.is_false_positive;
            const statusBadge = isFP ? '<span class="fp-badge">Faux positif</span>' : '';
            const actions = isFP
                ? `<button class="btn btn-sm btn-secondary" onclick="dashboard.unmarkFalsePositive(${inc.id})">Annuler FP</button>`
                : `<button class="btn btn-sm btn-warning" onclick="dashboard.openFpModal(${inc.id}, '${inc.ip_address}', ${inc.risk_score || 0}, '${inc.risk_level || ''}', '${inc.action_taken || ''}')">Marquer FP</button>
                   <button class="btn btn-sm btn-secondary" onclick="dashboard.showDetails(${JSON.stringify(inc).replace(/"/g, '&quot;')})">Details</button>`;
            return `
                <tr class="${isFP ? 'fp-row' : ''}">
                    <td>${inc.id}</td>
                    <td class="ip">${inc.ip_address}</td>
                    <td>${(inc.risk_score || 0).toFixed(4)}</td>
                    <td><span class="risk-${inc.risk_level}">${inc.risk_level?.toUpperCase()}</span></td>
                    <td>${inc.action_taken || '-'}</td>
                    <td>${this.formatDate(inc.timestamp)}</td>
                    <td>${statusBadge}</td>
                    <td>${actions}</td>
                </tr>
            `;
        }).join('');
    }

    renderBlockedTable(blocked) {
        const tbody = document.getElementById('blocked-body');
        if (!tbody) return;
        tbody.innerHTML = blocked.map(b => `
            <tr>
                <td class="ip">${b.ip_address}</td>
                <td>${this.formatDate(b.blocked_at)}</td>
                <td>${this.formatDate(b.block_until)}</td>
                <td>${b.reason || '-'}</td>
                <td>${b.block_count}</td>
                <td><button class="btn btn-sm btn-danger" onclick="dashboard.unblockIP('${b.ip_address}')">Debloquer</button></td>
            </tr>
        `).join('');
    }

    renderTrafficTable(traffic) {
        const tbody = document.getElementById('traffic-body');
        if (!tbody) return;
        const entries = Object.entries(traffic)
            .sort((a, b) => b[1].packet_count - a[1].packet_count)
            .slice(0, 50);

        if (entries.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;color:#9ca3af;padding:2rem">En attente de trafic reseau...</td></tr>`;
            return;
        }

        const portServices = {
            20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 67: 'DHCP', 68: 'DHCP', 80: 'HTTP', 110: 'POP3',
            123: 'NTP', 135: 'MSRPC', 137: 'NetBIOS', 138: 'NetBIOS',
            139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP', 162: 'SNMP',
            389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
            514: 'Syslog', 515: 'LPR', 587: 'Submission', 631: 'IPP',
            636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S', 1080: 'SOCKS',
            1433: 'MSSQL', 1434: 'MSSQL', 1521: 'Oracle', 1723: 'PPTP',
            2049: 'NFS', 2082: 'cPanel', 2083: 'cPanel-SSL',
            3306: 'MySQL', 3389: 'RDP', 3690: 'SVN', 4444: 'Metasploit',
            5060: 'SIP', 5432: 'PostgreSQL', 5900: 'VNC', 5984: 'CouchDB',
            6379: 'Redis', 6667: 'IRC', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
            8888: 'HTTP-Alt', 9090: 'Webmin', 9200: 'Elasticsearch',
            11211: 'Memcached', 27017: 'MongoDB', 27018: 'MongoDB',
        };

        tbody.innerHTML = entries.map(([ip, s]) => {
            const services = (s.ports || [])
                .filter(p => portServices[p])
                .map(p => `${p}/${portServices[p]}`)
                .join(', ');
            return `
                <tr>
                    <td class="ip">${ip}</td>
                    <td>${this.formatNumber(s.packet_count)}</td>
                    <td>${this.formatBytes(s.total_bytes)}</td>
                    <td>${s.unique_ports}</td>
                    <td class="services">${services || '-'}</td>
                    <td>${s.frequency?.toFixed(2)}/s</td>
                    <td>${(s.protocols || []).join(', ')}</td>
                    <td>${s.syn_count}</td>
                </tr>
            `;
        }).join('');
    }

    renderAlertsList(alerts) {
        const list = document.getElementById('recent-alerts-list');
        if (!list) return;
        list.innerHTML = alerts.slice(-20).reverse().map(a => {
            const d = a.data || {};
            return `
                <div class="alert-item">
                    <span class="ip">${d.ip_address || 'N/A'}</span>
                    <span class="score risk-${d.risk_level}">${(d.risk_score || 0).toFixed(4)}</span>
                    <span>${d.risk_level?.toUpperCase()}</span>
                    <span>${this.formatDate(d.timestamp)}</span>
                </div>
            `;
        }).join('');
    }

    renderLogs(logs) {
        const container = document.getElementById('logs-container');
        if (!container) return;
        container.innerHTML = logs.map(l => `
            <div class="log-entry ${l.severity}">
                <span class="timestamp">${this.formatDate(l.timestamp)}</span>
                <span>[${l.severity?.toUpperCase()}]</span>
                ${l.ip_address ? `<span class="ip">${l.ip_address}</span>` : ''}
                <span>${l.message}</span>
            </div>
        `).join('');
    }

    updateChartsFromIncidents(incidents) {
        if (!this.frontendCapabilities.charts || !this.charts.alerts || !this.charts.risk || !this.charts.topIps) {
            return;
        }

        const counts = { faible: 0, moyen: 0, critique: 0 };
        const ipScores = {};

        incidents.forEach(inc => {
            if (counts.hasOwnProperty(inc.risk_level)) {
                counts[inc.risk_level]++;
            }
            if (!ipScores[inc.ip_address] || ipScores[inc.ip_address] < inc.risk_score) {
                ipScores[inc.ip_address] = inc.risk_score;
            }
        });

        this.charts.alerts.data.datasets[0].data = [counts.faible, counts.moyen, counts.critique];
        this.charts.alerts.update();

        const now = new Date().toLocaleTimeString();
        this.riskHistory.labels.push(now);
        this.riskHistory.faible.push(counts.faible);
        this.riskHistory.moyen.push(counts.moyen);
        this.riskHistory.critique.push(counts.critique);

        if (this.riskHistory.labels.length > 30) {
            this.riskHistory.labels.shift();
            this.riskHistory.faible.shift();
            this.riskHistory.moyen.shift();
            this.riskHistory.critique.shift();
        }

        this.charts.risk.data.labels = this.riskHistory.labels;
        this.charts.risk.data.datasets[0].data = this.riskHistory.faible;
        this.charts.risk.data.datasets[1].data = this.riskHistory.moyen;
        this.charts.risk.data.datasets[2].data = this.riskHistory.critique;
        this.charts.risk.update();

        const sortedIps = Object.entries(ipScores)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10);
        this.charts.topIps.data.labels = sortedIps.map(e => e[0]);
        this.charts.topIps.data.datasets[0].data = sortedIps.map(e => e[1]);
        this.charts.topIps.data.datasets[0].backgroundColor = sortedIps.map(e => {
            if (e[1] >= 0.7) return 'rgba(239,68,68,0.8)';   // critique = rouge
            if (e[1] >= 0.3) return 'rgba(234,179,8,0.8)';   // moyen = jaune
            return 'rgba(16,185,129,0.8)';                     // faible = vert
        });
        this.charts.topIps.update();
    }

    updateTrafficChart(traffic) {
        if (!this.frontendCapabilities.charts || !this.charts.traffic) {
            return;
        }

        let totalPackets = 0;
        let totalBytes = 0;
        Object.values(traffic).forEach(s => {
            totalPackets += s.packet_count || 0;
            totalBytes += s.total_bytes || 0;
        });

        const now = new Date().toLocaleTimeString();
        this.trafficHistory.labels.push(now);
        this.trafficHistory.packets.push(totalPackets);
        this.trafficHistory.bytes.push(Math.round(totalBytes / 1024));

        if (this.trafficHistory.labels.length > 30) {
            this.trafficHistory.labels.shift();
            this.trafficHistory.packets.shift();
            this.trafficHistory.bytes.shift();
        }

        this.charts.traffic.data.labels = this.trafficHistory.labels;
        this.charts.traffic.data.datasets[0].data = this.trafficHistory.packets;
        this.charts.traffic.data.datasets[1].data = this.trafficHistory.bytes;
        this.charts.traffic.update();
    }

    handleAlert(data) {
        if (data.type === 'incident') {
            const d = data.data || {};
            if (d.risk_level === 'critique') {
                this.showPopup(d);
            }
        }
    }

    showPopup(data) {
        const popup = document.getElementById('alert-popup');
        popup.innerHTML = `
            <strong style="color: ${data.risk_level === 'critique' ? '#ef4444' : '#f59e0b'}">
                ALERTE ${data.risk_level?.toUpperCase()}
            </strong>
            <div>IP: ${data.ip_address}</div>
            <div>Score: ${(data.risk_score || 0).toFixed(4)}</div>
            <div>Action: ${data.action_taken}</div>
            <div style="font-size: 0.75rem; color: #9ca3af">${this.formatDate(data.timestamp)}</div>
        `;
        popup.classList.remove('hidden');
        setTimeout(() => popup.classList.add('hidden'), 10000);
    }

    showDetails(incident) {
        const details = incident.details || {};
        alert(`Incident #${incident.id}\nIP: ${incident.ip_address}\nScore: ${incident.risk_score}\nNiveau: ${incident.risk_level}\nAction: ${incident.action_taken}\n\nDetails:\n${JSON.stringify(details, null, 2)}`);
    }

    async unblockIP(ip) {
        if (!confirm(`Debloquer l'IP ${ip} ?`)) return;
        try {
            const resp = await fetch(`/api/blocked-ips/${ip}/unblock`, { method: 'POST' });
            const result = await resp.json();
            if (result.unblocked) {
                this.fetchBlocked();
            }
        } catch (e) {
            alert('Erreur lors du deblocage');
        }
    }

    // ─── Faux Positifs ───────────────────────────────────────

    _currentFpIncident = null;

    openFpModal(incidentId, ip, score, level, action) {
        this._currentFpIncident = incidentId;
        document.getElementById('fp-modal-info').innerHTML = `
            <div>Incident <strong>#${incidentId}</strong></div>
            <div>IP: <span class="ip">${ip}</span></div>
            <div>Score: ${score.toFixed(4)} | Niveau: ${level} | Action: ${action}</div>
        `;
        document.getElementById('fp-reason').value = '';
        document.getElementById('fp-category').value = 'other';
        document.getElementById('fp-auto-unblock').checked = true;
        document.getElementById('fp-add-whitelist').checked = false;
        document.getElementById('fp-whitelist-duration').value = '';
        document.getElementById('fp-whitelist-duration-field').style.display = 'none';
        document.getElementById('fp-modal').classList.remove('hidden');

        document.getElementById('fp-add-whitelist').onchange = (e) => {
            document.getElementById('fp-whitelist-duration-field').style.display =
                e.target.checked ? 'block' : 'none';
        };
    }

    closeFpModal() {
        document.getElementById('fp-modal').classList.add('hidden');
        this._currentFpIncident = null;
    }

    async confirmFalsePositive() {
        if (!this._currentFpIncident) return;
        const reason = document.getElementById('fp-reason').value.trim();
        if (!reason) {
            alert('Veuillez fournir une raison');
            return;
        }
        const category = document.getElementById('fp-category').value;
        const autoUnblock = document.getElementById('fp-auto-unblock').checked;
        const addToWhitelist = document.getElementById('fp-add-whitelist').checked;
        const durationStr = document.getElementById('fp-whitelist-duration').value;
        const whitelistDurationHours = durationStr ? parseInt(durationStr) : null;

        try {
            const resp = await fetch(`/api/false-positives/${this._currentFpIncident}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    reason,
                    category,
                    auto_unblock: autoUnblock,
                    add_to_whitelist: addToWhitelist,
                    whitelist_duration_hours: whitelistDurationHours,
                }),
            });
            const result = await resp.json();
            if (result.fp) {
                this.closeFpModal();
                this.fetchIncidents();
                this.fetchFalsePositives();
                this.fetchBlocked();
                this.fetchWhitelist();
            } else {
                alert(result.error || 'Erreur lors du marquage');
            }
        } catch (e) {
            alert('Erreur lors du marquage comme faux positif');
        }
    }

    async unmarkFalsePositive(incidentId) {
        if (!confirm('Annuler le marquage faux positif ?')) return;
        try {
            const resp = await fetch(`/api/false-positives/${incidentId}`, { method: 'DELETE' });
            const result = await resp.json();
            if (result.success) {
                this.fetchIncidents();
                this.fetchFalsePositives();
            }
        } catch (e) {
            alert('Erreur lors de l\'annulation');
        }
    }

    async fetchFalsePositives() {
        const fps = await this.apiFetch('/api/false-positives?limit=100');
        if (fps) this.renderFalsePositivesTable(fps);

        const stats = await this.apiFetch('/api/false-positives/stats');
        if (stats) this.renderFpStats(stats);
    }

    renderFalsePositivesTable(fps) {
        const tbody = document.getElementById('fp-body');
        if (!tbody) return;
        tbody.innerHTML = fps.map(fp => `
            <tr>
                <td>#${fp.incident_id}</td>
                <td class="ip">${fp.ip_address}</td>
                <td>${this.formatFpCategory(fp.category)}</td>
                <td>${fp.reason || '-'}</td>
                <td>${(fp.original_risk_score || 0).toFixed(4)}</td>
                <td>${this.formatDate(fp.marked_at)}</td>
                <td>
                    <button class="btn btn-sm btn-secondary" onclick="dashboard.unmarkFalsePositive(${fp.incident_id})">Annuler</button>
                </td>
            </tr>
        `).join('');
    }

    renderFpStats(stats) {
        const grid = document.getElementById('fp-stats-grid');
        if (!grid) return;
        grid.innerHTML = `
            <div class="fp-stat-card">
                <div class="fp-stat-value">${stats.total_false_positives || 0}</div>
                <div class="fp-stat-label">Total faux positifs</div>
            </div>
            <div class="fp-stat-card">
                <div class="fp-stat-value">${((stats.fp_rate || 0) * 100).toFixed(1)}%</div>
                <div class="fp-stat-label">Taux de FP</div>
            </div>
            <div class="fp-stat-card">
                <div class="fp-stat-value">${stats.total_incidents || 0}</div>
                <div class="fp-stat-label">Total incidents</div>
            </div>
        `;
    }

    formatFpCategory(cat) {
        const map = {
            legitimate_traffic: 'Trafic legitime',
            scheduled_task: 'Tache planifiee',
            monitoring_tool: 'Monitoring',
            backup_activity: 'Sauvegarde',
            known_service: 'Service connu',
            scanner_fp: 'Scanner FP',
            ai_model_error: 'Erreur IA',
            other: 'Autre',
        };
        return map[cat] || cat;
    }

    // ─── Liste Blanche ────────────────────────────────────────

    async fetchWhitelist() {
        try {
            console.log('Fetching whitelist...');
            const entries = await this.apiFetch('/api/whitelist');
            console.log('Whitelist entries:', entries);
            if (entries) this.renderWhitelistTable(entries);
        } catch(e) {
            console.error('Erreur whitelist:', e);
        }
    }

    renderWhitelistTable(entries) {
        console.log('Rendering whitelist:', entries);
        const tbody = document.getElementById('whitelist-body');
        if (!tbody) {
            console.error('tbody not found!');
            return;
        }
        if (!entries || entries.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:#9ca3af">Aucune IP dans la whitelist</td></tr>';
            return;
        }
        tbody.innerHTML = entries.map(e => `
            <tr>
                <td class="ip">${e.ip_address}</td>
                <td>${e.reason || '-'}</td>
                <td>${e.source || '-'}</td>
                <td>${this.formatDate(e.added_at)}</td>
                <td>${e.expires_at ? this.formatDate(e.expires_at) : 'Permanent'}</td>
                <td>
                    <button class="btn btn-sm btn-danger" onclick="dashboard.removeFromWhitelist('${e.ip_address}')">Retirer</button>
                </td>
            </tr>
        `).join('');
    }

    async addToWhitelist() {
        const ip = document.getElementById('wl-ip').value.trim();
        const reason = document.getElementById('wl-reason').value.trim();
        const expiresStr = document.getElementById('wl-expires').value;

        if (!ip || !reason) {
            alert('IP et raison sont requis');
            return;
        }

        try {
            const resp = await fetch('/api/whitelist', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    ip_address: ip,
                    reason: reason,
                    expires_hours: expiresStr ? parseInt(expiresStr) : null,
                }),
            });
            const result = await resp.json();
            if (result.added) {
                document.getElementById('wl-ip').value = '';
                document.getElementById('wl-reason').value = '';
                document.getElementById('wl-expires').value = '';
                this.fetchWhitelist();
            } else {
                alert(result.error || 'Erreur lors de l\'ajout');
            }
        } catch (e) {
            alert('Erreur lors de l\'ajout a la liste blanche');
        }
    }

    async removeFromWhitelist(ip) {
        if (!confirm(`Retirer ${ip} de la liste blanche ?`)) return;
        try {
            const resp = await fetch(`/api/whitelist/${ip}`, { method: 'DELETE' });
            const result = await resp.json();
            if (result.removed) {
                this.fetchWhitelist();
            }
        } catch (e) {
            alert('Erreur lors du retrait');
        }
    }

    setupEventListeners() {
        document.getElementById('filter-btn')?.addEventListener('click', () => this.fetchIncidents());
        document.getElementById('filter-ip')?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.fetchIncidents();
        });

        document.getElementById('export-json-btn')?.addEventListener('click', () => {
            window.open('/api/incidents/export?fmt=json', '_blank');
        });
        document.getElementById('export-csv-btn')?.addEventListener('click', () => {
            window.open('/api/incidents/export?fmt=csv', '_blank');
        });

        document.getElementById('log-filter-btn')?.addEventListener('click', () => {
            const severity = document.getElementById('log-severity')?.value;
            const ip = document.getElementById('log-ip')?.value;
            this.fetchLogs(severity, ip);
        });

        let resizeTimer = null;
        window.addEventListener('resize', () => {
            clearTimeout(resizeTimer);
            resizeTimer = setTimeout(() => this.resizeGlobeViewport(), 120);
        });
    }

    formatNumber(n) {
        if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
        if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
        return String(Math.round(n));
    }

    formatBytes(bytes) {
        if (bytes >= 1073741824) return (bytes / 1073741824).toFixed(1) + ' GB';
        if (bytes >= 1048576) return (bytes / 1048576).toFixed(1) + ' MB';
        if (bytes >= 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return bytes + ' B';
    }

    formatUptime(seconds) {
        const h = Math.floor(seconds / 3600);
        const m = Math.floor((seconds % 3600) / 60);
        const s = Math.floor(seconds % 60);
        if (h > 0) return `${h}h ${m}m`;
        if (m > 0) return `${m}m ${s}s`;
        return `${s}s`;
    }

    formatDate(ts) {
        if (!ts) return '-';
        const d = new Date(ts);
        if (isNaN(d.getTime())) return ts;
        return d.toLocaleString('fr-FR');
    }
}

const dashboard = new Dashboard();
