/* Campaign detail charts: interaction funnel + timeline. */
(function () {
  "use strict";
  document.addEventListener("DOMContentLoaded", function () {
    if (typeof Chart === "undefined") return;
    var data = window.PhishGuard && window.PhishGuard.readJSON("campaign-data");
    if (!data) return;

    var GRID = "rgba(33,48,77,.6)";
    var TEXT = "#8da2c0";
    Chart.defaults.color = TEXT;
    Chart.defaults.font.size = 11;

    var funnel = document.getElementById("chartFunnel");
    if (funnel) {
      new Chart(funnel.getContext("2d"), {
        type: "bar",
        data: {
          labels: ["Participants", "Opened", "Clicked", "Training viewed", "Reported"],
          datasets: [{
            label: "Unique demo users",
            data: data.funnel,
            backgroundColor: ["#3d8bfd", "#4dabf7", "#ff4d4f", "#f0b429", "#2ecc71"],
            borderRadius: 5
          }]
        },
        options: {
          indexAxis: "y", responsive: true, maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { beginAtZero: true, grid: { color: GRID }, ticks: { color: TEXT, precision: 0 } },
            y: { grid: { display: false }, ticks: { color: TEXT } }
          }
        }
      });
    }

    var timeline = document.getElementById("chartTimeline");
    if (timeline && data.timeline.labels.length) {
      new Chart(timeline.getContext("2d"), {
        type: "line",
        data: {
          labels: data.timeline.labels,
          datasets: [
            { label: "Opened", data: data.timeline.opened, borderColor: "#4dabf7", backgroundColor: "#4dabf733", tension: .3, fill: true, borderWidth: 2 },
            { label: "Clicked", data: data.timeline.clicked, borderColor: "#ff4d4f", backgroundColor: "#ff4d4f33", tension: .3, fill: true, borderWidth: 2 },
            { label: "Reported", data: data.timeline.reported, borderColor: "#2ecc71", backgroundColor: "#2ecc7133", tension: .3, fill: true, borderWidth: 2 }
          ]
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { position: "bottom" } },
          scales: {
            x: { grid: { color: GRID }, ticks: { color: TEXT } },
            y: { beginAtZero: true, grid: { color: GRID }, ticks: { color: TEXT, precision: 0 } }
          }
        }
      });
    }
  });
})();
