/* Detection result visualisations: indicator contribution + ML attribution. */
(function () {
  "use strict";
  document.addEventListener("DOMContentLoaded", function () {
    if (typeof Chart === "undefined") return;
    var data = window.PhishGuard && window.PhishGuard.readJSON("detector-data");
    if (!data) return;

    var GRID = "rgba(33,48,77,.6)";
    var TEXT = "#8da2c0";
    Chart.defaults.color = TEXT;
    Chart.defaults.font.size = 11;

    var indicators = document.getElementById("chartIndicators");
    if (indicators && data.indicators && data.indicators.labels.length) {
      new Chart(indicators.getContext("2d"), {
        type: "bar",
        data: {
          labels: data.indicators.labels,
          datasets: [{
            label: "Points contributed",
            data: data.indicators.values,
            backgroundColor: data.indicators.colors,
            borderRadius: 4
          }]
        },
        options: {
          indexAxis: "y", responsive: true, maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { beginAtZero: true, grid: { color: GRID }, ticks: { color: TEXT } },
            y: { grid: { display: false }, ticks: { color: TEXT, font: { size: 10 } } }
          }
        }
      });
    }

    var attribution = document.getElementById("chartAttribution");
    if (attribution && data.attribution && data.attribution.labels.length) {
      new Chart(attribution.getContext("2d"), {
        type: "bar",
        data: {
          labels: data.attribution.labels,
          datasets: [{
            label: "Approximate contribution",
            data: data.attribution.values,
            backgroundColor: data.attribution.values.map(function (v) {
              return v >= 0 ? "#ff7a45" : "#2ecc71";
            }),
            borderRadius: 4
          }]
        },
        options: {
          indexAxis: "y", responsive: true, maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { grid: { color: GRID }, ticks: { color: TEXT } },
            y: { grid: { display: false }, ticks: { color: TEXT, font: { size: 10 } } }
          }
        }
      });
    }
  });
})();
