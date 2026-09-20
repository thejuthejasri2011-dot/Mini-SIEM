function filterAlerts() {

    const ipFilter = document.getElementById("ipFilter").value.toLowerCase();
    const severityFilter = document.getElementById("severityFilter").value;
    const threatFilter = document.getElementById("threatFilter").value;
    const statusFilter = document.getElementById("statusFilter").value;

    const rows = document.querySelectorAll("#alertsTable tr");

    rows.forEach(row => {

        const cells = row.querySelectorAll("td");

        // Ignore rows without alert data
        if (cells.length < 5) {
            return;
        }

        const severity = cells[2].textContent.trim();
const threat = cells[3].textContent.trim();
const ip = cells[4].textContent.trim().toLowerCase();

        const ipMatch =
            ipFilter === "" || ip.includes(ipFilter);

        const severityMatch =
            severityFilter === "ALL" ||
            severity === severityFilter;

        const threatMatch =
            threatFilter === "ALL" ||
            threat === threatFilter;

            const status = cells[5].querySelector("select").value;

const statusMatch =
    statusFilter === "ALL" ||
    status === statusFilter;

        if (ipMatch && severityMatch && threatMatch && statusMatch) {
            row.style.display = "";
        } else {
            row.style.display = "none";
        }

    });
}


function clearFilters() {

    document.getElementById("ipFilter").value = "";

    document.getElementById("severityFilter").value = "ALL";

    document.getElementById("threatFilter").value = "ALL";

    const rows = document.querySelectorAll("#alertsTable tr");

    rows.forEach(row => {
        row.style.display = "";
    });
}

// ==========================================
// PROFESSIONAL THREAT ACTIVITY CHART
// ==========================================

function drawThreatActivityChart() {

    const canvas = document.getElementById("threatActivityChart");

    if (!canvas) {
        return;
    }

    const rows = document.querySelectorAll("#alertsTable tr");

    const alerts = [];

    rows.forEach(row => {

        const cells = row.querySelectorAll("td");

        if (cells.length >= 5) {

            const timestamp = cells[1].textContent.trim();
            const severity = cells[2].textContent.trim();

            alerts.push({
                timestamp: timestamp,
                severity: severity
            });
        }
    });

    const ctx = canvas.getContext("2d");

    const width = canvas.parentElement.clientWidth;

    canvas.width = width;
    canvas.height = 300;

    ctx.clearRect(0, 0, canvas.width, canvas.height);

    if (alerts.length === 0) {

        ctx.fillStyle = "#64748b";
        ctx.font = "14px Arial";
        ctx.textAlign = "center";

        ctx.fillText(
            "No alert activity available",
            canvas.width / 2,
            canvas.height / 2
        );

        return;
    }

    const left = 55;
    const right = 25;
    const top = 25;
    const bottom = 65;

    const chartWidth =
        canvas.width - left - right;

    const chartHeight =
        canvas.height - top - bottom;

    const maxHeight = 5;

    const barGap = 18;

    const barWidth =
        Math.max(
            28,
            (chartWidth / alerts.length) - barGap
        );

    // Reverse so oldest alerts appear first.
    alerts.reverse();

    // ------------------------------------------
    // GRID
    // ------------------------------------------

    ctx.strokeStyle = "rgba(148, 163, 184, 0.12)";
    ctx.lineWidth = 1;

    for (let i = 0; i <= maxHeight; i++) {

        const y =
            top +
            chartHeight -
            (i / maxHeight) * chartHeight;

        ctx.beginPath();

        ctx.moveTo(left, y);
        ctx.lineTo(canvas.width - right, y);

        ctx.stroke();
    }

    // ------------------------------------------
    // Y AXIS
    // ------------------------------------------

    ctx.fillStyle = "#64748b";
    ctx.font = "10px Arial";
    ctx.textAlign = "right";

    for (let i = 0; i <= maxHeight; i++) {

        const y =
            top +
            chartHeight -
            (i / maxHeight) * chartHeight;

        ctx.fillText(
            i,
            left - 10,
            y + 4
        );
    }

    // ------------------------------------------
    // ALERT BARS
    // ------------------------------------------

    alerts.forEach((alert, index) => {

        let value = 1;
        let color = "#38bdf8";

        if (alert.severity === "CRITICAL") {
            value = 5;
            color = "#ff6b6b";
        }
        else if (alert.severity === "HIGH") {
            value = 4;
            color = "#ff9f43";
        }
        else if (alert.severity === "MEDIUM") {
            value = 3;
            color = "#ffd166";
        }
        else if (alert.severity === "LOW") {
            value = 2;
            color = "#38bdf8";
        }

        const x =
            left +
            index *
            (chartWidth / alerts.length) +
            barGap / 2;

        const height =
            (value / maxHeight) *
            chartHeight;

        const y =
            top +
            chartHeight -
            height;

        // Bar
        ctx.fillStyle = color;

        ctx.beginPath();

        ctx.roundRect(
            x,
            y,
            barWidth,
            height,
            5
        );

        ctx.fill();

        // Severity label
        ctx.fillStyle = "#e2e8f0";

        ctx.font = "9px Arial";
        ctx.textAlign = "center";

        ctx.fillText(
            alert.severity,
            x + barWidth / 2,
            y - 8
        );

        // Timestamp
        let timeLabel = alert.timestamp;

        if (timeLabel.length > 10) {
            timeLabel = timeLabel.substring(11, 16);
        }

        ctx.fillStyle = "#64748b";

        ctx.font = "10px Arial";

        ctx.fillText(
            timeLabel,
            x + barWidth / 2,
            canvas.height - 25
        );
    });

    // ------------------------------------------
    // X AXIS
    // ------------------------------------------

    ctx.strokeStyle = "rgba(148, 163, 184, 0.25)";

    ctx.beginPath();

    ctx.moveTo(left, top + chartHeight);

    ctx.lineTo(
        canvas.width - right,
        top + chartHeight
    );

    ctx.stroke();
}


// Draw chart when dashboard loads
window.addEventListener(
    "load",
    drawThreatActivityChart
);


// Redraw chart when browser size changes
window.addEventListener(
    "resize",
    drawThreatActivityChart
);