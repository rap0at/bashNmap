document.addEventListener('DOMContentLoaded', () => {
    const attackBtn = document.getElementById('attack-btn');
    const reportBtn = document.getElementById('report-btn');
    const targetInput = document.getElementById('target');
    const output = document.getElementById('output');
    let intervalId;

    attackBtn.addEventListener('click', () => {
        const target = targetInput.value;
        if (!target) {
            output.textContent += '[-] Please enter a target.\n';
            return;
        }

        output.textContent = `[*] Starting attack on ${target}...
`;
        attackBtn.disabled = true;

        fetch('/attack', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ target }),
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'started') {
                intervalId = setInterval(getStatus, 1000);
            } else {
                output.textContent += `[-] Error starting attack: ${data.error}\n`;
                attackBtn.disabled = false;
            }
        })
        .catch(error => {
            output.textContent += `[-] Network error: ${error}\n`;
            attackBtn.disabled = false;
        });
    });

    reportBtn.addEventListener('click', () => {
        fetch('/report')
            .then(response => response.text())
            .then(html => {
                const newWindow = window.open();
                newWindow.document.write(html);
                newWindow.document.close();
            });
    });

    function getStatus() {
        fetch('/status')
            .then(response => response.json())
            .then(data => {
                output.textContent = data.log;
                if (data.completed) {
                    clearInterval(intervalId);
                    attackBtn.disabled = false;
                    output.textContent += '\n[*] Attack finished.\n';
                }
            });
    }
});
