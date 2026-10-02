/* PhishGuard dashboard charts (Chart.js, vendored locally). */
(function () {
  "use strict";

  document.addEventListener("DOMContentLoaded", function () {
    if (typeof Chart === "undefined") return;
    var data = window.PhishGuard && window.PhishGuard.readJSON("dashboard-data");
    if (!data) return;

    var GRID = "rgba(33,48,77,.6)";
    var TEXT = "#8da2c0";
    var RISK = { LOW: "#2ecc71", MEDIUM: "#f0b429", HIGH: "#ff7a45", CRITICAL: "#ff4d4f" };

    Chart.defaults.color = TEXT;
    Chart.defaults.font.family = '"Segoe UI", Roboto, system-ui, sans-serif';
    Chart.defaults.font.size = 11;
    Chart.defaults.plugins.legend.labels.boxWidth = 10;
    Chart.defaults.plugins.legend.labels.usePointStyle = true;
    Chart.defaults.animation.duration = 500;

    function scales(extra) {
      var base = {
        x: { grid: { color: GRID, drawBorder: false }, ticks: { color: TEXT } },
        y: { grid: { color: GRID, drawBorder: false }, ticks: { color: TEXT }, beginAtZero: true }
      };
      return Object.assign(base, extra || {});
    }

    function make(id, config) {
      var canvas = document.getElementById(id);
      if (!canvas) return null;
      return new Chart(canvas.getContext("2d"), config);
    }

    /* 1. Simulation activity over time */
    var activity = data.charts.activity;
    make("chartActivity", {
      type: "line",
      data: {
        labels: activity.labels,
        datasets: [
          series("Opened", activity.series.OPENED, "#4dabf7"),
          series("Link clicked", activity.series.LINK_CLICKED, "#ff4d4f"),
          series("Training viewed", activity.series.TRAINING_PAGE_VIEWED, "#f0b429"),
          series("Reported", activity.series.REPORTED, "#2ecc71")
        ]
      },
      options: {
        responsive: true, maintainAspectRatio: false, interaction: { mode: "index", intersect: false },
        plugins: { legend: { position: "bottom" } }, scales: scales()
      }
    });

    function series(label, values, colour) {
      return {
        label: label, data: values, borderColor: colour,
        backgroundColor: colour + "22", borderWidth: 2, tension: .32,
        pointRadius: 2, pointHoverRadius: 4, fill: true
      };
    }

    /* 2. Risk distribution of analysed artefacts */
    var risk = data.charts.risk_distribution;
    make("chartRisk", {
      type: "doughnut",
      data: {
        labels: risk.labels,
        datasets: [{
          data: risk.values,
          backgroundColor: risk.labels.map(function (l) { return RISK[l]; }),
          borderColor: "#0e1524", borderWidth: 2
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false, cutout: "62%",
        plugins: { legend: { position: "bottom" } }
      }
    });

    /* 3. Detection accuracy of the ML candidates */
    var accuracy = data.accuracy;
    if (accuracy && accuracy.available) {
      make("chartAccuracy", {
        type: "bar",
        data: {
          labels: accuracy.labels,
          datasets: [
            { label: "Accuracy", data: accuracy.accuracy, backgroundColor: "#3d8bfd" },
            { label: "Precision", data: accuracy.precision, backgroundColor: "#23d5ab" },
            { label: "Recall", data: accuracy.recall, backgroundColor: "#f0b429" },
            { label: "F1", data: accuracy.f1, backgroundColor: "#ff7a45" }
          ]
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { position: "bottom" } },
          scales: scales({ y: { min: 50, max: 100, grid: { color: GRID }, ticks: { color: TEXT } } })
        }
      });
    }

    /* 4. Campaign performance */
    var perf = data.charts.campaign_performance;
    make("chartCampaigns", {
      type: "bar",
      data: {
        labels: perf.labels,
        datasets: [
          { label: "Interaction rate %", data: perf.interaction, backgroundColor: "#ff4d4f" },
          { label: "Report rate %", data: perf.reporting, backgroundColor: "#2ecc71" },
          { label: "Awareness score", data: perf.awareness, type: "line", borderColor: "#3d8bfd",
            backgroundColor: "#3d8bfd33", borderWidth: 2, tension: .3, pointRadius: 3, fill: false }
        ]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { position: "bottom" } },
        scales: scales({ y: { beginAtZero: true, max: 100, grid: { color: GRID }, ticks: { color: TEXT } } })
      }
    });

    /* 5. Email vs URL detections */
    var split = data.charts.detection_split;
    make("chartSplit", {
      type: "polarArea",
      data: {
        labels: split.labels,
        datasets: [{
          data: split.values,
          backgroundColor: ["rgba(61,139,253,.65)", "rgba(35,213,171,.65)"],
          borderColor: "#0e1524", borderWidth: 2
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { position: "bottom" } },
        scales: { r: { grid: { color: GRID }, ticks: { display: false }, angleLines: { color: GRID } } }
      }
    });

    /* 6. Awareness improvement over time */
    var improvement = data.charts.awareness_improvement;
    make("chartAwareness", {
      type: "line",
      data: {
        labels: improvement.labels,
        datasets: [{
          label: "Mean quiz score %", data: improvement.values,
          borderColor: "#23d5ab", backgroundColor: "rgba(35,213,171,.18)",
          borderWidth: 2, tension: .3, pointRadius: 3, fill: true
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: scales({ y: { beginAtZero: true, max: 100, grid: { color: GRID }, ticks: { color: TEXT } } })
      }
    });
  });
})();
