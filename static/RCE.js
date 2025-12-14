document.addEventListener('DOMContentLoaded', () => {
    // --- Establish WebSocket connection ---
    const socket = io();

    // --- DOM Element References ---
    const targetInput = document.getElementById('target');
    const attackBtn = document.getElementById('attack-btn');
    const outputPre = document.getElementById('output');
    const reportBtn = document.getElementById('report-btn');
    const scanCheckboxes = document.querySelectorAll('input[name="scans"]');

    let reportContent = '';

    // --- Event Listeners ---

    // Handle Attack Button Click
    attackBtn.addEventListener('click', () => {
        const target = targetInput.value.trim();
        if (!target) {
            alert('Please provide a target URL.');
            return;
        }

        const selectedScans = {};
        scanCheckboxes.forEach(checkbox => {
            selectedScans[checkbox.value] = checkbox.checked;
        });

        // Disable UI elements during attack
        attackBtn.disabled = true;
        reportBtn.classList.add('hidden');
        outputPre.textContent = ''; // Clear previous output

        // Initiate attack via WebSocket
        socket.emit('start_attack', { 
            target: target,
            scans: selectedScans
        });
    });

    // Handle Report Button Click
    reportBtn.addEventListener('click', () => {
        if (!reportContent) {
            alert('No report content available.');
            return;
        }
        
        const blob = new Blob([reportContent], { type: 'text/markdown' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'raptor_scan_report.md';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(a.href);
    });


    // --- WebSocket Event Handlers ---

    socket.on('connect', () => {
        console.log('Connected to server.');
    });

    // Handle incoming log messages
    socket.on('log', (data) => {
        const { tool, msg } = data;
        const coloredMsg = `[${tool}] ${msg}\n`;
        outputPre.textContent += coloredMsg;
        // Auto-scroll to the bottom
        outputPre.scrollTop = outputPre.scrollHeight;
    });

    // Handle attack completion
    socket.on('attack_complete', (data) => {
        attackBtn.disabled = false; // Re-enable button
        if (data.report) {
            reportContent = data.report;
            reportBtn.classList.remove('hidden'); // Show report button
        }
    });

    socket.on('disconnect', () => {
        console.log('Disconnected from server.');
        // Optionally, add a message to the UI
        outputPre.textContent += '\n[SYSTEM] Connection to server lost. Please refresh.';
    });
});
