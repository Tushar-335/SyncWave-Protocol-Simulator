const { createApp, ref, computed, watch, nextTick } = Vue;

const app = createApp({
    setup() {
        const activity = ref('browsing');
        
        // Form Inputs
        const inputs = ref({
            url: 'https://example.com',
            to: 'student@university.edu',
            subject: 'Assignment 1',
            body: 'Here is the assignment file attached.',
            quality: '1080p'
        });

        // Activity Logs
        const logs = ref([]);
        const logContainer = ref(null);

        // Simulation State
        const isRunning = ref(false);
        const isFinished = ref(false);
        
        // Protocol visualization state
        const allSteps = ref([]);
        const currentStepIndex = ref(-1);
        const isStarted = ref(false);
        const isPaused = ref(false);
        
        let playInterval = null;

        const visibleSteps = computed(() => {
            if (!isStarted.value) return [];
            return allSteps.value.slice(0, currentStepIndex.value + 1);
        });

        const setActivity = (newActivity) => {
            if (isRunning.value) return; // prevent change while running
            activity.value = newActivity;
            resetSimulation();
        };

        const addLog = (msg, type = 'info') => {
            const time = new Date().toLocaleTimeString([], { hour12: false });
            logs.value.push({ time, msg, type });
            nextTick(() => {
                if (logContainer.value) {
                    logContainer.value.scrollTop = logContainer.value.scrollHeight;
                }
            });
        };

        // Escapes HTML and applies highlighting to specific keywords
        const highlightMessage = (msg, keywords) => {
            // First escape the message entirely to avoid XSS and parsing issues
            let escaped = msg
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;");
            
            if (keywords && keywords.length) {
                keywords.forEach(kw => {
                    const escapedKw = kw
                        .replace(/&/g, "&amp;")
                        .replace(/</g, "&lt;")
                        .replace(/>/g, "&gt;");
                    // Using regex to replace all instances of the keyword, ignoring case
                    const regex = new RegExp(`(${escapeRegExp(escapedKw)})`, 'gi');
                    escaped = escaped.replace(regex, `<span class="highlight-field">$1</span>`);
                });
            }
            return escaped;
        };

        const escapeRegExp = (string) => {
            return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        };

        const scrollSequenceToBottom = () => {
            nextTick(() => {
                const container = document.getElementById('sequence-container');
                if (container) {
                    container.scrollTop = container.scrollHeight;
                }
            });
        };

        // --- Data Definitions for Protocol Sequences ---
        
        const getBrowsingSequence = () => {
            const domain = (inputs.value.url.match(/https?:\/\/([^/]+)/) || [])[1] || 'example.com';
            return [
                { protocol: 'DNS', dir: 'c2s', msg: `DNS Query\nQuestion: ${domain} (A)`, highlight: [domain] },
                { protocol: 'DNS', dir: 's2c', msg: `DNS Response\nAnswer: ${domain} -> 93.184.216.34`, highlight: ['93.184.216.34'] },
                { protocol: 'TCP', dir: 'c2s', msg: `TCP SYN\nSeq=0`, highlight: ['SYN'] },
                { protocol: 'TCP', dir: 's2c', msg: `TCP SYN-ACK\nSeq=0, Ack=1`, highlight: ['SYN-ACK'] },
                { protocol: 'TCP', dir: 'c2s', msg: `TCP ACK\nSeq=1, Ack=1`, highlight: ['ACK'] },
                { protocol: 'HTTP', dir: 'c2s', msg: `GET / HTTP/1.1\nHost: ${domain}\nUser-Agent: NetVizBrowser/1.0\nAccept: text/html`, highlight: ['GET / HTTP/1.1', `Host: ${domain}`] },
                { protocol: 'HTTP', dir: 's2c', msg: `HTTP/1.1 200 OK\nContent-Type: text/html\nContent-Length: 1256\n\n<html>...</html>`, highlight: ['200 OK', 'Content-Type: text/html'] }
            ];
        };

        const getMailSequence = () => {
            const toDomain = inputs.value.to.split('@')[1] || 'domain.com';
            const sender = 'user@local.com';
            return [
                { protocol: 'DNS', dir: 'c2s', msg: `DNS Query\nQuestion: _smtp._tcp.${toDomain} (MX)`, highlight: ['MX', toDomain] },
                { protocol: 'DNS', dir: 's2c', msg: `DNS Response\nAnswer: mail.${toDomain} (IP: 198.51.100.2)`, highlight: [`mail.${toDomain}`] },
                { protocol: 'TCP', dir: 's2c', msg: `220 mail.${toDomain} ESMTP Postfix`, highlight: ['220'] },
                { protocol: 'SMTP', dir: 'c2s', msg: `EHLO local.com`, highlight: ['EHLO local.com'] },
                { protocol: 'SMTP', dir: 's2c', msg: `250-mail.${toDomain} Hello local.com\n250-SIZE 35651584\n250 ENHANCEDSTATUSCODES`, highlight: ['250'] },
                { protocol: 'SMTP', dir: 'c2s', msg: `MAIL FROM:<${sender}>`, highlight: [`MAIL FROM:<${sender}>`] },
                { protocol: 'SMTP', dir: 's2c', msg: `250 2.1.0 Ok`, highlight: ['250 2.1.0 Ok'] },
                { protocol: 'SMTP', dir: 'c2s', msg: `RCPT TO:<${inputs.value.to}>`, highlight: [`RCPT TO:<${inputs.value.to}>`] },
                { protocol: 'SMTP', dir: 's2c', msg: `250 2.1.5 Ok`, highlight: ['250 2.1.5 Ok'] },
                { protocol: 'SMTP', dir: 'c2s', msg: `DATA`, highlight: ['DATA'] },
                { protocol: 'SMTP', dir: 's2c', msg: `354 End data with <CR><LF>.<CR><LF>`, highlight: ['354'] },
                { protocol: 'SMTP', dir: 'c2s', msg: `Subject: ${inputs.value.subject}\nTo: ${inputs.value.to}\n\n${inputs.value.body}\n.`, highlight: [inputs.value.subject, '.'] },
                { protocol: 'SMTP', dir: 's2c', msg: `250 2.0.0 Ok: queued as 1A2B3C4D`, highlight: ['queued'] },
                { protocol: 'SMTP', dir: 'c2s', msg: `QUIT`, highlight: ['QUIT'] },
                { protocol: 'SMTP', dir: 's2c', msg: `221 2.0.0 Bye`, highlight: ['221'] }
            ];
        };

        const getStreamingSequence = () => {
            return [
                { protocol: 'DNS', dir: 'c2s', msg: `DNS Query\nQuestion: cdn.stream.net (A)`, highlight: ['cdn.stream.net'] },
                { protocol: 'DNS', dir: 's2c', msg: `DNS Response\nAnswer: cdn.stream.net -> 203.0.113.5`, highlight: ['203.0.113.5'] },
                { protocol: 'HTTP', dir: 'c2s', msg: `GET /video/master.m3u8 HTTP/1.1\nHost: cdn.stream.net`, highlight: ['GET /video/master.m3u8'] },
                { protocol: 'HTTP', dir: 's2c', msg: `HTTP/1.1 200 OK\nContent-Type: application/vnd.apple.mpegurl\n\n#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=5000000,RESOLUTION=1920x1080\n1080p.m3u8`, highlight: ['200 OK', 'application/vnd.apple.mpegurl'] },
                { protocol: 'HTTP', dir: 'c2s', msg: `GET /video/${inputs.value.quality}.m3u8 HTTP/1.1\nHost: cdn.stream.net`, highlight: [`GET /video/${inputs.value.quality}.m3u8`] },
                { protocol: 'HTTP', dir: 's2c', msg: `HTTP/1.1 200 OK\nContent-Type: application/vnd.apple.mpegurl\n\n#EXTM3U\n#EXTINF:4.000,\nsegment1.ts`, highlight: ['200 OK', 'segment1.ts'] },
                { protocol: 'HTTP', dir: 'c2s', msg: `GET /video/segment1.ts HTTP/1.1\nHost: cdn.stream.net`, highlight: ['GET /video/segment1.ts'] },
                { protocol: 'HTTP', dir: 's2c', msg: `HTTP/1.1 200 OK\nContent-Type: video/mp2t\n\n[BINARY VIDEO DATA]`, highlight: ['video/mp2t'] }
            ];
        };

        // --- Simulation Control ---

        const resetSimulation = () => {
            stopAutoPlay();
            isRunning.value = false;
            isFinished.value = false;
            isStarted.value = false;
            isPaused.value = false;
            currentStepIndex.value = -1;
            allSteps.value = [];
            logs.value = [];
        };

        const startSimulation = () => {
            resetSimulation();
            isRunning.value = true;
            isStarted.value = true;
            isFinished.value = false;
            isPaused.value = false;
            
            addLog(`Starting ${activity.value} activity...`, 'success');

            if (activity.value === 'browsing') {
                allSteps.value = getBrowsingSequence();
                addLog(`Navigating to ${inputs.value.url}`);
            } else if (activity.value === 'mail') {
                allSteps.value = getMailSequence();
                addLog(`Composing email to ${inputs.value.to}`);
            } else if (activity.value === 'streaming') {
                allSteps.value = getStreamingSequence();
                addLog(`Requesting stream at ${inputs.value.quality}`);
            }

            // Start automated playback
            startAutoPlay();
        };

        const startAutoPlay = () => {
            if (playInterval) clearInterval(playInterval);
            isPaused.value = false;
            playInterval = setInterval(() => {
                if (currentStepIndex.value < allSteps.value.length - 1) {
                    currentStepIndex.value++;
                    addLog(`Protocol exchange: ${allSteps.value[currentStepIndex.value].protocol}`);
                    scrollSequenceToBottom();
                } else {
                    stopAutoPlay();
                    isRunning.value = false;
                    isFinished.value = true;
                    addLog('Activity completed successfully.', 'success');
                }
            }, 1200); // 1.2s per step for animation visibility
        };

        const stopAutoPlay = () => {
            if (playInterval) {
                clearInterval(playInterval);
                playInterval = null;
            }
        };

        const togglePause = () => {
            if (!isStarted.value) return;
            isPaused.value = !isPaused.value;
            if (isPaused.value) {
                stopAutoPlay();
                addLog('Visualization paused.', 'info');
            } else {
                startAutoPlay();
                addLog('Visualization resumed.', 'info');
            }
        };

        const stepForward = () => {
            if (currentStepIndex.value < allSteps.value.length - 1) {
                stopAutoPlay();
                isPaused.value = true;
                currentStepIndex.value++;
                addLog(`Stepped forward to: ${allSteps.value[currentStepIndex.value].protocol}`);
                scrollSequenceToBottom();
                
                if (currentStepIndex.value === allSteps.value.length - 1) {
                    isRunning.value = false;
                    isFinished.value = true;
                }
            }
        };

        const stepBackward = () => {
            if (currentStepIndex.value > 0) {
                stopAutoPlay();
                isPaused.value = true;
                currentStepIndex.value--;
                isRunning.value = true; 
                isFinished.value = false;
                addLog(`Stepped backward.`);
            }
        };

        const replay = () => {
            stopAutoPlay();
            currentStepIndex.value = -1;
            isRunning.value = true;
            isFinished.value = false;
            logs.value = [];
            addLog(`Replaying ${activity.value} visualization...`, 'success');
            startAutoPlay();
        };

        return {
            activity,
            inputs,
            logs,
            logContainer,
            isRunning,
            isFinished,
            allSteps,
            currentStepIndex,
            visibleSteps,
            isStarted,
            isPaused,
            totalSteps: computed(() => allSteps.value.length),
            setActivity,
            startSimulation,
            togglePause,
            stepForward,
            stepBackward,
            replay,
            highlightMessage
        };
    }
});

app.mount('#app');
