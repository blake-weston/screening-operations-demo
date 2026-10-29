<?php

declare(strict_types=1);

date_default_timezone_set('Europe/London');

require __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/scan_events_repository.php';

$user = require_auth();
$allowedRiskLevels = allowed_risk_levels();
$allowedTerminals = allowed_terminals();
$allowedLaneNumbers = allowed_lane_numbers();
$activeFilters = normalize_scan_event_filters($_GET);
$riskLevel = $activeFilters['risk_level'];
$terminal = $activeFilters['terminal'];
$laneNumber = $activeFilters['lane_number'];
$payload = fetch_scan_event_dashboard_payload($user, $activeFilters);
$summary = $payload['summary'];
$scanEvents = $payload['events'];

render_header('Scan Events');
?>
<main class="grid">
  <section class="card">
    <h1>Airport Security Scan Events</h1>
    <p class="muted">
      Current date and time: <span class="code"><?= escape_html(date('Y-m-d H:i:s')) ?></span>
    </p>
    <div class="grid-three" id="scan-summary">
      <div class="metric">
        <span class="muted">Total events</span>
        <span class="metric-value" data-summary="total-events"><?= escape_html((string) ($summary['total_events'] ?? '0')) ?></span>
      </div>
      <div class="metric">
        <span class="muted">High-risk events</span>
        <span class="metric-value" data-summary="high-risk-events"><?= escape_html((string) ($summary['high_risk_events'] ?? '0')) ?></span>
      </div>
      <div class="metric">
        <span class="muted">Latest scan</span>
        <span class="metric-value metric-value-small" data-summary="latest-scan-time"><?= escape_html((string) ($summary['latest_scan_time'] ?? 'N/A')) ?></span>
      </div>
    </div>
  </section>

  <section class="card">
    <h2>Filter events</h2>
    <form method="get" action="/index.php">
      <label for="risk_level">Risk level</label>
      <select id="risk_level" name="risk_level">
        <option value="">All risk levels</option>
        <?php foreach ($allowedRiskLevels as $allowedRiskOption): ?>
          <option value="<?= escape_html($allowedRiskOption) ?>"<?= $riskLevel === $allowedRiskOption ? ' selected' : '' ?>>
            <?= escape_html($allowedRiskOption) ?>
          </option>
        <?php endforeach; ?>
      </select>

      <label for="terminal">Terminal</label>
      <select id="terminal" name="terminal">
        <option value="">All terminals</option>
        <?php foreach ($allowedTerminals as $allowedTerminal): ?>
          <option value="<?= escape_html($allowedTerminal) ?>"<?= $terminal === $allowedTerminal ? ' selected' : '' ?>>
            <?= escape_html($allowedTerminal) ?>
          </option>
        <?php endforeach; ?>
      </select>

      <label for="lane_number">Lane number</label>
      <select id="lane_number" name="lane_number">
        <option value="">All lanes</option>
        <?php foreach ($allowedLaneNumbers as $allowedLaneNumber): ?>
          <option value="<?= escape_html((string) $allowedLaneNumber) ?>"<?= $laneNumber === $allowedLaneNumber ? ' selected' : '' ?>>
            Lane <?= escape_html((string) $allowedLaneNumber) ?>
          </option>
        <?php endforeach; ?>
      </select>

      <div class="actions">
        <button type="submit">Apply filters</button>
        <a class="button button-secondary" href="/index.php">Clear</a>
      </div>
    </form>
  </section>
</main>

<section class="card card-spaced">
  <h2>Event log</h2>
  <p class="muted" id="scan-refresh-status">Event log auto-refreshes every 15 seconds.</p>
  <div id="scan-event-log">
  <?php if ($scanEvents === []): ?>
    <p class="muted">No scan events match the current filter set.</p>
  <?php else: ?>
    <table>
      <thead>
        <tr>
          <th>ID</th>
          <th>Threat image</th>
          <th>Scan time</th>
          <th>Location</th>
          <th>Risk</th>
          <th>Threat</th>
          <th>Notes</th>
          <th>Event notes</th>
        </tr>
      </thead>
      <tbody>
        <?php foreach ($scanEvents as $scanEvent): ?>
          <tr>
            <td><?= escape_html((string) $scanEvent['id']) ?></td>
            <td>
              <?php if (!empty($scanEvent['has_thumbnail'])): ?>
                <button
                  type="button"
                  class="thumb-link"
                  data-full-image="/media.php?event_id=<?= escape_html((string) $scanEvent['id']) ?>&kind=full"
                  data-image-caption="Threat image for event <?= escape_html((string) $scanEvent['id']) ?>"
                  aria-label="Open threat image for event <?= escape_html((string) $scanEvent['id']) ?>"
                >
                  <img
                    class="thumb-image"
                    src="/media.php?event_id=<?= escape_html((string) $scanEvent['id']) ?>&kind=thumb"
                    alt="Threat image for event <?= escape_html((string) $scanEvent['id']) ?>"
                  >
                </button>
              <?php else: ?>
                <div class="thumb-placeholder">No threat image imported</div>
              <?php endif; ?>
            </td>
            <td><?= escape_html($scanEvent['scan_time']) ?></td>
            <td><?= escape_html($scanEvent['scanner_location']) ?></td>
            <td><span class="<?= escape_html(risk_badge_class($scanEvent['risk_level'])) ?>"><?= escape_html($scanEvent['risk_level']) ?></span></td>
            <td><?= escape_html($scanEvent['threat_category']) ?></td>
            <td><?= escape_html($scanEvent['notes']) ?></td>
            <td>
              <a
                class="icon-button note-link"
                href="/notes.php?event_id=<?= escape_html((string) $scanEvent['id']) ?>"
                aria-label="View notes for event <?= escape_html((string) $scanEvent['id']) ?>"
                data-tooltip="View notes"
              ><span class="material-icons" aria-hidden="true">description</span></a>
            </td>
          </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
  <?php endif; ?>
  </div>
</section>
<div id="image-modal" class="image-modal" hidden>
  <div class="image-modal-dialog" role="dialog" aria-modal="true" aria-labelledby="image-modal-caption">
    <button type="button" class="image-modal-close" id="image-modal-close" aria-label="Close image preview">&times;</button>
    <figure class="image-modal-figure">
      <img id="image-modal-full" class="image-modal-full" src="" alt="">
      <figcaption id="image-modal-caption" class="image-modal-caption"></figcaption>
    </figure>
  </div>
</div>
<script nonce="<?= escape_html($cspNonce) ?>">
  (function () {
    const summaryNodes = {
      totalEvents: document.querySelector('[data-summary="total-events"]'),
      highRiskEvents: document.querySelector('[data-summary="high-risk-events"]'),
      latestScanTime: document.querySelector('[data-summary="latest-scan-time"]')
    };
    const eventLogNode = document.getElementById('scan-event-log');
    const statusNode = document.getElementById('scan-refresh-status');
    const formNode = document.querySelector('form[action="/index.php"]');
    const imageModalNode = document.getElementById('image-modal');
    const imageModalFullNode = document.getElementById('image-modal-full');
    const imageModalCaptionNode = document.getElementById('image-modal-caption');
    const imageModalCloseNode = document.getElementById('image-modal-close');
    const refreshIntervalMs = 15000;
    let lastTriggerNode = null;

    function escapeHtml(value) {
      return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }

    function riskBadgeClass(riskLevel) {
      const normalized = String(riskLevel).toLowerCase();
      if (normalized === 'low') return 'badge badge-low';
      if (normalized === 'medium') return 'badge badge-medium';
      if (normalized === 'high') return 'badge badge-high';
      return 'badge';
    }

    function openImageModal(imageUrl, caption) {
      imageModalFullNode.src = imageUrl;
      imageModalFullNode.alt = caption;
      imageModalCaptionNode.textContent = caption;
      imageModalNode.hidden = false;
      document.body.style.overflow = 'hidden';
      imageModalCloseNode.focus();
    }

    function closeImageModal() {
      imageModalNode.hidden = true;
      imageModalFullNode.src = '';
      imageModalFullNode.alt = '';
      imageModalCaptionNode.textContent = '';
      document.body.style.overflow = '';

      if (lastTriggerNode instanceof HTMLElement) {
        lastTriggerNode.focus();
      }
    }

    function renderEventLog(events) {
      if (!Array.isArray(events) || events.length === 0) {
        eventLogNode.innerHTML = '<p class="muted">No scan events match the current filter set.</p>';
        return;
      }

      const rows = events.map((event) => {
        const imageCell = event.has_thumbnail
          ? `<button
              type="button"
              class="thumb-link"
              data-full-image="/media.php?event_id=${encodeURIComponent(event.id)}&kind=full"
              data-image-caption="Threat image for event ${escapeHtml(event.id)}"
              aria-label="Open threat image for event ${escapeHtml(event.id)}"
            >
              <img class="thumb-image" src="/media.php?event_id=${encodeURIComponent(event.id)}&kind=thumb" alt="Threat image for event ${escapeHtml(event.id)}">
            </button>`
          : '<div class="thumb-placeholder">No threat image imported</div>';

        return `<tr>
          <td>${escapeHtml(event.id)}</td>
          <td>${imageCell}</td>
          <td>${escapeHtml(event.scan_time)}</td>
          <td>${escapeHtml(event.scanner_location)}</td>
          <td><span class="${escapeHtml(riskBadgeClass(event.risk_level))}">${escapeHtml(event.risk_level)}</span></td>
          <td>${escapeHtml(event.threat_category)}</td>
          <td>${escapeHtml(event.notes)}</td>
          <td><a
            class="icon-button note-link"
            href="/notes.php?event_id=${encodeURIComponent(event.id)}"
            aria-label="View notes for event ${escapeHtml(event.id)}"
            data-tooltip="View notes"
          ><span class="material-icons" aria-hidden="true">description</span></a></td>
        </tr>`;
      }).join('');

      eventLogNode.innerHTML = `<table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Threat image</th>
            <th>Scan time</th>
            <th>Location</th>
            <th>Risk</th>
            <th>Threat</th>
            <th>Notes</th>
            <th>Event notes</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>`;
    }

    async function refreshDashboard() {
      const query = new URLSearchParams(new FormData(formNode)).toString();
      const url = `/scan_events_data.php${query ? `?${query}` : ''}`;

      try {
        const response = await fetch(url, {
          headers: { 'Accept': 'application/json' },
          credentials: 'same-origin',
          cache: 'no-store'
        });

        if (!response.ok) {
          throw new Error(`Refresh failed with status ${response.status}`);
        }

        const payload = await response.json();
        summaryNodes.totalEvents.textContent = String(payload.summary.total_events ?? 0);
        summaryNodes.highRiskEvents.textContent = String(payload.summary.high_risk_events ?? 0);
        summaryNodes.latestScanTime.textContent = payload.summary.latest_scan_time || 'N/A';
        renderEventLog(payload.events || []);
        statusNode.textContent = `Last refreshed at ${new Date().toLocaleTimeString()}. Auto-refreshes every 15 seconds.`;
      } catch (error) {
        statusNode.textContent = 'Auto-refresh failed temporarily. Displaying the last loaded event state.';
      }
    }

    eventLogNode.addEventListener('click', function (event) {
      const triggerNode = event.target.closest('[data-full-image]');
      if (!(triggerNode instanceof HTMLElement)) {
        return;
      }

      lastTriggerNode = triggerNode;
      openImageModal(triggerNode.dataset.fullImage || '', triggerNode.dataset.imageCaption || 'Threat image preview');
    });

    imageModalCloseNode.addEventListener('click', closeImageModal);

    imageModalNode.addEventListener('click', function (event) {
      if (event.target === imageModalNode) {
        closeImageModal();
      }
    });

    document.addEventListener('keydown', function (event) {
      if (event.key === 'Escape' && !imageModalNode.hidden) {
        closeImageModal();
      }
    });

    window.setInterval(refreshDashboard, refreshIntervalMs);
  }());
</script>
<?php
render_footer();
