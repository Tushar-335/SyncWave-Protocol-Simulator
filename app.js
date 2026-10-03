const { createApp, ref, computed, watch, nextTick } = Vue;

const app = createApp({
    setup() {
        const activity = ref('browsing');
        const activeLayer = ref('app'); // 'app' or 'transport'
        
        // Form Inputs
        const inputs = ref({
            url: 'https://example.com',
            to: 'student@university.edu',
            subject: 'Assignment 2',
            body: 'TCP handshake analysis attached.',
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

        const getActiveLayerData = (step) => {
            return activeLayer.value === 'app' ? step.app : step.transport;
        };

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

        const highlightMessage = (msg, keywords) => {
            if (!msg) return '';
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

        // --- Data Definitions for Dual-Layer Protocol Sequences ---
        
        const getBrowsingSequence = () => {
            const domain = (inputs.value.url.match(/https?:\/\/([^/]+)/) || [])[1] || 'example.com';
            return [
                {
                    dir: 'c2s',
                    app: { protocol: 'DNS', msg: `DNS Query\nQuestion: ${domain} (A)`, highlight: [domain] },
                    transport: { protocol: 'UDP', msg: `Src Port: 53211  Dst Port: 53\nLength: 42\nChecksum: 0x8a2b`, highlight: ['53', 'UDP'] }
                },
                {
                    dir: 's2c',
                    app: { protocol: 'DNS', msg: `DNS Response\nAnswer: ${domain} -> 93.184.216.34`, highlight: ['93.184.216.34'] },
                    transport: { protocol: 'UDP', msg: `Src Port: 53  Dst Port: 53211\nLength: 58\nChecksum: 0x1f3c`, highlight: ['53', 'UDP'] }
                },
                {
                    dir: 'c2s',
                    app: { protocol: 'SYSTEM', msg: `Opening TCP Socket to 93.184.216.34:443...`, highlight: ['Socket'] },
                    transport: { protocol: 'TCP', msg: `Flags: [SYN]\nSeq: 0\nAck: 0\nWin: 64240\nLen: 0`, highlight: ['[SYN]', 'Seq: 0'] }
                },
                {
                    dir: 's2c',
                    app: { protocol: 'SYSTEM', msg: `Socket Connecting...`, highlight: [] },
                    transport: { protocol: 'TCP', msg: `Flags: [SYN, ACK]\nSeq: 0\nAck: 1\nWin: 65535\nLen: 0`, highlight: ['[SYN, ACK]', 'Ack: 1'] }
                },
                {
                    dir: 'c2s',
                    app: { protocol: 'SYSTEM', msg: `Socket Connected`, highlight: ['Connected'] },
                    transport: { protocol: 'TCP', msg: `Flags: [ACK]\nSeq: 1\nAck: 1\nWin: 64240\nLen: 0`, highlight: ['[ACK]'] }
                },
                {
                    dir: 'c2s',
                    app: { protocol: 'HTTP', msg: `GET / HTTP/1.1\nHost: ${domain}\nUser-Agent: SyncWave/2.0\nAccept: text/html`, highlight: ['GET / HTTP/1.1'] },
                    transport: { protocol: 'TCP', msg: `Flags: [PSH, ACK]\nSeq: 1\nAck: 1\nWin: 64240\nLen: 145`, highlight: ['[PSH, ACK]', 'Len: 145'] }
                },
                {
                    dir: 's2c',
                    app: { protocol: 'SYSTEM', msg: `Server Acknowledges Request Data`, highlight: [] },
                    transport: { protocol: 'TCP', msg: `Flags: [ACK]\nSeq: 1\nAck: 146\nWin: 65535\nLen: 0`, highlight: ['[ACK]'] }
                },
                {
                    dir: 's2c',
                    app: { protocol: 'HTTP', msg: `HTTP/1.1 200 OK\nContent-Type: text/html\nContent-Length: 1256\n\n<html>...</html>`, highlight: ['200 OK'] },
                    transport: { protocol: 'TCP', msg: `Flags: [PSH, ACK]\nSeq: 1\nAck: 146\nWin: 65535\nLen: 1256`, highlight: ['[PSH, ACK]', 'Len: 1256'] }
                },
                {
                    dir: 'c2s',
                    app: { protocol: 'SYSTEM', msg: `Closing Connection (Client Fin)`, highlight: ['Closing'] },
                    transport: { protocol: 'TCP', msg: `Flags: [FIN, ACK]\nSeq: 146\nAck: 1257\nWin: 64240\nLen: 0`, highlight: ['[FIN, ACK]'] }
                },
                {
                    dir: 's2c',
                    app: { protocol: 'SYSTEM', msg: `Server Acknowledges Close`, highlight: [] },
                    transport: { protocol: 'TCP', msg: `Flags: [FIN, ACK]\nSeq: 1257\nAck: 147\nWin: 65535\nLen: 0`, highlight: ['[FIN, ACK]'] }
                },
                {
                    dir: 'c2s',
                    app: { protocol: 'SYSTEM', msg: `Connection Terminated`, highlight: ['Terminated'] },
                    transport: { protocol: 'TCP', msg: `Flags: [ACK]\nSeq: 147\nAck: 1258\nWin: 64240\nLen: 0`, highlight: ['[ACK]'] }
                }
            ];
        };

        const getMailSequence = () => {
            const toDomain = inputs.value.to.split('@')[1] || 'domain.com';
            const sender = 'user@local.com';
            return [
                {
                    dir: 'c2s',
                    app: { protocol: 'DNS', msg: `DNS Query\nQuestion: _smtp._tcp.${toDomain} (MX)`, highlight: ['MX', toDomain] },
                    transport: { protocol: 'UDP', msg: `Src Port: 60111  Dst Port: 53\nLength: 48`, highlight: ['53', 'UDP'] }
                },
                {
                    dir: 's2c',
                    app: { protocol: 'DNS', msg: `DNS Response\nAnswer: mail.${toDomain} (IP: 198.51.100.2)`, highlight: [`mail.${toDomain}`] },
                    transport: { protocol: 'UDP', msg: `Src Port: 53  Dst Port: 60111\nLength: 64`, highlight: ['53', 'UDP'] }
                },
                {
                    dir: 'c2s',
                    app: { protocol: 'SYSTEM', msg: `Opening TCP Socket to 198.51.100.2:25 (SMTP)...`, highlight: ['Socket'] },
                    transport: { protocol: 'TCP', msg: `Flags: [SYN]\nSeq: 0\nAck: 0\nWin: 64240\nLen: 0`, highlight: ['[SYN]'] }
                },
                {
                    dir: 's2c',
                    app: { protocol: 'SYSTEM', msg: `Socket Connecting...`, highlight: [] },
                    transport: { protocol: 'TCP', msg: `Flags: [SYN, ACK]\nSeq: 0\nAck: 1\nWin: 65535\nLen: 0`, highlight: ['[SYN, ACK]'] }
                },
                {
                    dir: 'c2s',
                    app: { protocol: 'SYSTEM', msg: `Socket Connected`, highlight: ['Connected'] },
                    transport: { protocol: 'TCP', msg: `Flags: [ACK]\nSeq: 1\nAck: 1\nWin: 64240\nLen: 0`, highlight: ['[ACK]'] }
                },
                {
                    dir: 's2c',
                    app: { protocol: 'SMTP', msg: `220 mail.${toDomain} ESMTP Postfix`, highlight: ['220'] },
                    transport: { protocol: 'TCP', msg: `Flags: [PSH, ACK]\nSeq: 1\nAck: 1\nWin: 65535\nLen: 45`, highlight: ['[PSH, ACK]'] }
                },
                {
                    dir: 'c2s',
                    app: { protocol: 'SMTP', msg: `EHLO local.com`, highlight: ['EHLO local.com'] },
                    transport: { protocol: 'TCP', msg: `Flags: [PSH, ACK]\nSeq: 1\nAck: 46\nWin: 64240\nLen: 16`, highlight: ['[PSH, ACK]'] }
                },
                {
                    dir: 's2c',
                    app: { protocol: 'SMTP', msg: `250-mail.${toDomain} Hello local.com\n250-SIZE 35651584\n250 ENHANCEDSTATUSCODES`, highlight: ['250'] },
                    transport: { protocol: 'TCP', msg: `Flags: [PSH, ACK]\nSeq: 46\nAck: 17\nWin: 65535\nLen: 85`, highlight: ['[PSH, ACK]'] }
                },
                {
                    dir: 'c2s',
                    app: { protocol: 'SMTP', msg: `MAIL FROM:<${sender}>`, highlight: [`MAIL FROM:<${sender}>`] },
                    transport: { protocol: 'TCP', msg: `Flags: [PSH, ACK]\nSeq: 17\nAck: 131\nWin: 64240\nLen: 35`, highlight: ['[PSH, ACK]'] }
                },
                {
                    dir: 's2c',
                    app: { protocol: 'SMTP', msg: `250 2.1.0 Ok`, highlight: ['250 2.1.0 Ok'] },
                    transport: { protocol: 'TCP', msg: `Flags: [PSH, ACK]\nSeq: 131\nAck: 52\nWin: 65535\nLen: 14`, highlight: ['[PSH, ACK]'] }
                },
                {
                    dir: 'c2s',
                    app: { protocol: 'SMTP', msg: `RCPT TO:<${inputs.value.to}>`, highlight: [`RCPT TO:<${inputs.value.to}>`] },
                    transport: { protocol: 'TCP', msg: `Flags: [PSH, ACK]\nSeq: 52\nAck: 145\nWin: 64240\nLen: 35`, highlight: ['[PSH, ACK]'] }
                },
                {
                    dir: 's2c',
                    app: { protocol: 'SMTP', msg: `250 2.1.5 Ok`, highlight: ['250 2.1.5 Ok'] },
                    transport: { protocol: 'TCP', msg: `Flags: [PSH, ACK]\nSeq: 145\nAck: 87\nWin: 65535\nLen: 14`, highlight: ['[PSH, ACK]'] }
                },
                {
                    dir: 'c2s',
                    app: { protocol: 'SMTP', msg: `DATA`, highlight: ['DATA'] },
                    transport: { protocol: 'TCP', msg: `Flags: [PSH, ACK]\nSeq: 87\nAck: 159\nWin: 64240\nLen: 6`, highlight: ['[PSH, ACK]'] }
                },
                {
                    dir: 's2c',
                    app: { protocol: 'SMTP', msg: `354 End data with <CR><LF>.<CR><LF>`, highlight: ['354'] },
                    transport: { protocol: 'TCP', msg: `Flags: [PSH, ACK]\nSeq: 159\nAck: 93\nWin: 65535\nLen: 37`, highlight: ['[PSH, ACK]'] }
                },
                {
                    dir: 'c2s',
                    app: { protocol: 'SMTP', msg: `Subject: ${inputs.value.subject}\nTo: ${inputs.value.to}\n\n${inputs.value.body}\n.`, highlight: [inputs.value.subject, '.'] },
                    transport: { protocol: 'TCP', msg: `Flags: [PSH, ACK]\nSeq: 93\nAck: 196\nWin: 64240\nLen: 245`, highlight: ['[PSH, ACK]'] }
                },
                {
                    dir: 's2c',
                    app: { protocol: 'SMTP', msg: `250 2.0.0 Ok: queued as 1A2B3C4D`, highlight: ['queued'] },
                    transport: { protocol: 'TCP', msg: `Flags: [PSH, ACK]\nSeq: 196\nAck: 338\nWin: 65535\nLen: 35`, highlight: ['[PSH, ACK]'] }
                },
                {
                    dir: 'c2s',
                    app: { protocol: 'SMTP', msg: `QUIT`, highlight: ['QUIT'] },
                    transport: { protocol: 'TCP', msg: `Flags: [PSH, ACK]\nSeq: 338\nAck: 231\nWin: 64240\nLen: 6`, highlight: ['[PSH, ACK]'] }
                },
                {
                    dir: 's2c',
                    app: { protocol: 'SMTP', msg: `221 2.0.0 Bye`, highlight: ['221'] },
                    transport: { protocol: 'TCP', msg: `Flags: [PSH, ACK]\nSeq: 231\nAck: 344\nWin: 65535\nLen: 15`, highlight: ['[PSH, ACK]'] }
                },
                {
                    dir: 'c2s',
                    app: { protocol: 'SYSTEM', msg: `Client Closing Connection`, highlight: [] },
                    transport: { protocol: 'TCP', msg: `Flags: [FIN, ACK]\nSeq: 344\nAck: 246\nWin: 64240\nLen: 0`, highlight: ['[FIN, ACK]'] }
                },
                {
                    dir: 's2c',
                    app: { protocol: 'SYSTEM', msg: `Server Acknowledges Close`, highlight: [] },
                    transport: { protocol: 'TCP', msg: `Flags: [FIN, ACK]\nSeq: 246\nAck: 345\nWin: 65535\nLen: 0`, highlight: ['[FIN, ACK]'] }
                },
                {
                    dir: 'c2s',
                    app: { protocol: 'SYSTEM', msg: `Connection Terminated`, highlight: ['Terminated'] },
                    transport: { protocol: 'TCP', msg: `Flags: [ACK]\nSeq: 345\nAck: 247\nWin: 64240\nLen: 0`, highlight: ['[ACK]'] }
                }
            ];
        };

        const getStreamingSequence = () => {
            return [
                {
                    dir: 'c2s',
                    app: { protocol: 'DNS', msg: `DNS Query\nQuestion: cdn.stream.net (A)`, highlight: ['cdn.stream.net'] },
                    transport: { protocol: 'UDP', msg: `Src Port: 60233  Dst Port: 53\nLength: 48`, highlight: ['UDP'] }
                },
                {
                    dir: 's2c',
                    app: { protocol: 'DNS', msg: `DNS Response\nAnswer: cdn.stream.net -> 203.0.113.5`, highlight: ['203.0.113.5'] },
                    transport: { protocol: 'UDP', msg: `Src Port: 53  Dst Port: 60233\nLength: 64`, highlight: ['UDP'] }
                },
                {
                    dir: 'c2s',
                    app: { protocol: 'SYSTEM', msg: `Opening TCP Socket to CDN (203.0.113.5:80)...`, highlight: ['Socket'] },
                    transport: { protocol: 'TCP', msg: `Flags: [SYN]\nSeq: 0\nAck: 0\nWin: 64240\nLen: 0`, highlight: ['[SYN]'] }
                },
                {
                    dir: 's2c',
                    app: { protocol: 'SYSTEM', msg: `Socket Connecting...`, highlight: [] },
                    transport: { protocol: 'TCP', msg: `Flags: [SYN, ACK]\nSeq: 0\nAck: 1\nWin: 65535\nLen: 0`, highlight: ['[SYN, ACK]'] }
                },
                {
                    dir: 'c2s',
                    app: { protocol: 'SYSTEM', msg: `Socket Connected`, highlight: ['Connected'] },
                    transport: { protocol: 'TCP', msg: `Flags: [ACK]\nSeq: 1\nAck: 1\nWin: 64240\nLen: 0`, highlight: ['[ACK]'] }
                },
                {
                    dir: 'c2s',
                    app: { protocol: 'HTTP', msg: `GET /video/master.m3u8 HTTP/1.1\nHost: cdn.stream.net`, highlight: ['GET /video/master.m3u8'] },
                    transport: { protocol: 'TCP', msg: `Flags: [PSH, ACK]\nSeq: 1\nAck: 1\nWin: 64240\nLen: 180`, highlight: ['[PSH, ACK]'] }
                },
                {
                    dir: 's2c',
                    app: { protocol: 'HTTP', msg: `HTTP/1.1 200 OK\nContent-Type: application/vnd.apple.mpegurl\n\n#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=5000000,RESOLUTION=1920x1080\n1080p.m3u8`, highlight: ['200 OK', 'application/vnd.apple.mpegurl'] },
                    transport: { protocol: 'TCP', msg: `Flags: [PSH, ACK]\nSeq: 1\nAck: 181\nWin: 65535\nLen: 345`, highlight: ['[PSH, ACK]'] }
                },
                {
                    dir: 'c2s',
                    app: { protocol: 'HTTP', msg: `GET /video/${inputs.value.quality}.m3u8 HTTP/1.1\nHost: cdn.stream.net`, highlight: [`GET /video/${inputs.value.quality}.m3u8`] },
                    transport: { protocol: 'TCP', msg: `Flags: [PSH, ACK]\nSeq: 181\nAck: 346\nWin: 64240\nLen: 180`, highlight: ['[PSH, ACK]'] }
                },
                {
                    dir: 's2c',
                    app: { protocol: 'HTTP', msg: `HTTP/1.1 200 OK\nContent-Type: application/vnd.apple.mpegurl\n\n#EXTM3U\n#EXTINF:4.000,\nsegment1.ts`, highlight: ['200 OK', 'segment1.ts'] },
                    transport: { protocol: 'TCP', msg: `Flags: [PSH, ACK]\nSeq: 346\nAck: 361\nWin: 65535\nLen: 320`, highlight: ['[PSH, ACK]'] }
                },
                {
                    dir: 'c2s',
                    app: { protocol: 'HTTP', msg: `GET /video/segment1.ts HTTP/1.1\nHost: cdn.stream.net`, highlight: ['GET /video/segment1.ts'] },
                    transport: { protocol: 'TCP', msg: `Flags: [PSH, ACK]\nSeq: 361\nAck: 667\nWin: 64240\nLen: 175`, highlight: ['[PSH, ACK]'] }
                },
                {
                    dir: 's2c',
                    app: { protocol: 'HTTP', msg: `HTTP/1.1 200 OK\nContent-Type: video/mp2t\n\n[BINARY VIDEO DATA - Chunk 1]`, highlight: ['video/mp2t'] },
                    transport: { protocol: 'TCP', msg: `Flags: [PSH, ACK]\nSeq: 667\nAck: 536\nWin: 65535\nLen: 1400`, highlight: ['[PSH, ACK]', 'Len: 1400'] }
                },
                {
                    dir: 's2c',
                    app: { protocol: 'HTTP', msg: `[BINARY VIDEO DATA - Chunk 2]`, highlight: [] },
                    transport: { protocol: 'TCP', msg: `Flags: [PSH, ACK]\nSeq: 2067\nAck: 536\nWin: 65535\nLen: 1400`, highlight: ['[PSH, ACK]'] }
                },
                {
                    dir: 'c2s',
                    app: { protocol: 'SYSTEM', msg: `Client Acknowledges Data`, highlight: [] },
                    transport: { protocol: 'TCP', msg: `Flags: [ACK]\nSeq: 536\nAck: 3467\nWin: 64240\nLen: 0`, highlight: ['[ACK]'] }
                }
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
                    const step = allSteps.value[currentStepIndex.value];
                    const msgProtocol = activeLayer.value === 'app' ? step.app.protocol : step.transport.protocol;
                    addLog(`Event dispatched: ${msgProtocol} exchange`);
                    scrollSequenceToBottom();
                } else {
                    stopAutoPlay();
                    isRunning.value = false;
                    isFinished.value = true;
                    addLog('Activity completed successfully.', 'success');
                }
            }, 1200); 
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
                const step = allSteps.value[currentStepIndex.value];
                addLog(`Stepped forward: ${step.app.protocol} / ${step.transport.protocol}`);
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
            activeLayer,
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
            getActiveLayerData,
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
