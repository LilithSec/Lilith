/*
 * Reusable time-window control shared across Lilith web forms.
 *
 * Markup contract (rendered by templates/partials/_time_range.html.ep): a
 * container with class "time-range" holding, keyed by data-role:
 *   preset      - <select>; numeric options are minutes-back, "custom" reveals the range
 *   custom      - the From/To wrapper (shown only for the custom preset)
 *   minutes     - hidden <input> (name=go_back_minutes) carrying the relative window
 *   start / end - hidden <input>s (name=start / end) carrying the absolute bounds
 *   {start,end}-date  - native <input type=date>
 *   {start,end}-hour  - <input type=number> 0-23 (24-hour, no AM/PM)
 *   {start,end}-min   - <input type=number> 0-59
 *
 * Only the active mode's params submit (the others are disabled): a preset
 * sends go_back_minutes; Custom composes 'YYYY-MM-DD HH:MM' into start/end on
 * submit. Self-initializes every .time-range on the page; also exposes
 * window.LilithTimeRange.{init,initAll} for dynamically added ones.
 */
(function () {
  function pad(num) { return (num < 10 ? '0' : '') + num; }

  function clampInt(value, low, high) {
    value = parseInt(value, 10);
    if (isNaN(value)) { return low; }
    return Math.max(low, Math.min(high, value));
  }

  function initOne(root) {
    if (root.dataset.trReady) { return; }   // idempotent
    root.dataset.trReady = '1';

    var byRole = function (role) { return root.querySelector('[data-role="' + role + '"]'); };
    var presetEl  = byRole('preset');
    var customEl  = byRole('custom');
    var minutesEl = byRole('minutes');
    var startEl   = byRole('start');
    var endEl     = byRole('end');
    if (!presetEl || !minutesEl || !startEl || !endEl) { return; }
    var formEl = root.closest('form');

    // Each end of the range: its date/hour/minute inputs and the whole-day time
    // it falls back to when the time is left unset (From -> 00:00, To -> 23:59).
    var bounds = {
      start: { dateEl: byRole('start-date'), hourEl: byRole('start-hour'), minEl: byRole('start-min'), defaultTime: [0, 0] },
      end:   { dateEl: byRole('end-date'),   hourEl: byRole('end-hour'),   minEl: byRole('end-min'),   defaultTime: [23, 59] }
    };

    function isCustom() { return presetEl.value === 'custom'; }

    // Show/hide the custom range and keep only the active mode's params live, so
    // the reader picks an explicit range over go_back_minutes accordingly.
    function syncMode() {
      if (customEl) { customEl.style.display = isCustom() ? '' : 'none'; }
      minutesEl.disabled = isCustom();
      startEl.disabled = !isCustom();
      endEl.disabled   = !isCustom();
      if (!isCustom()) { minutesEl.value = presetEl.value; }
    }

    // 'YYYY-MM-DD HH:MM' from one bound, or '' with no date. An unset time falls
    // back to that bound's whole-day default (From 00:00, To 23:59).
    function compose(bound) {
      if (!bound || !bound.dateEl || !bound.dateEl.value) { return ''; }
      var hour   = bound.hourEl.value === '' ? bound.defaultTime[0] : clampInt(bound.hourEl.value, 0, 23);
      var minute = bound.minEl.value === ''  ? bound.defaultTime[1] : clampInt(bound.minEl.value, 0, 59);
      return bound.dateEl.value + ' ' + pad(hour) + ':' + pad(minute);
    }

    // Seed one bound's fields from a 'YYYY-MM-DD[ T]HH:MM' string.
    function seedBound(bound, value) {
      var match = /^(\d{4}-\d{2}-\d{2})[ T](\d{1,2}):(\d{2})/.exec(value || '');
      if (match && bound && bound.dateEl) {
        bound.dateEl.value = match[1];
        bound.hourEl.value = parseInt(match[2], 10);
        bound.minEl.value  = parseInt(match[3], 10);
      }
    }

    // When a date is picked, surface that bound's default time (only if the user
    // hasn't set one) so the whole-day bound is visible and still editable.
    function wireDefaultTime(bound) {
      if (!bound.dateEl) { return; }
      bound.dateEl.addEventListener('change', function () {
        if (!bound.dateEl.value) { return; }
        if (bound.hourEl.value === '') { bound.hourEl.value = bound.defaultTime[0]; }
        if (bound.minEl.value === '')  { bound.minEl.value = bound.defaultTime[1]; }
      });
    }
    // The current window as the params a form would submit: a relative preset
    // gives go_back_minutes; Custom gives composed start/end. Lets JS consumers
    // (the dashboards) read the control without a form submit.
    function readWindow() {
      if (isCustom()) { return { go_back_minutes: '', start: compose(bounds.start), end: compose(bounds.end) }; }
      return { go_back_minutes: presetEl.value, start: '', end: '' };
    }

    // Point the control at a relative preset (used when a saved view loads),
    // snapping to a day when the value is not one of the presets.
    function setWindow(windowSpec) {
      var minutes = windowSpec && windowSpec.go_back_minutes != null ? String(windowSpec.go_back_minutes) : '';
      presetEl.value = minutes;
      if (presetEl.value !== minutes) { presetEl.value = '1440'; }
      syncMode();
    }

    function fireChange() { root.dispatchEvent(new CustomEvent('timerange:change')); }

    wireDefaultTime(bounds.start);
    wireDefaultTime(bounds.end);

    // Notify live consumers when the window changes (form pages ignore this).
    presetEl.addEventListener('change', function () { syncMode(); fireChange(); });
    [bounds.start, bounds.end].forEach(function (bound) {
      [bound.dateEl, bound.hourEl, bound.minEl].forEach(function (input) {
        if (input) { input.addEventListener('change', fireChange); }
      });
    });
    if (formEl) {
      formEl.addEventListener('submit', function () {
        if (isCustom()) { startEl.value = compose(bounds.start); endEl.value = compose(bounds.end); }
      });
    }

    // Open in Custom when an absolute bound is already present; seed its fields.
    if (startEl.value || endEl.value) {
      presetEl.value = 'custom';
      seedBound(bounds.start, startEl.value);
      seedBound(bounds.end, endEl.value);
    }
    syncMode();

    root._trApi = { read: readWindow, set: setWindow };
  }

  function initAll(scope) {
    (scope || document).querySelectorAll('.time-range').forEach(initOne);
  }

  window.LilithTimeRange = {
    init: initOne,
    initAll: initAll,
    read: function (root) { return root && root._trApi ? root._trApi.read() : null; },
    set:  function (root, windowSpec) { if (root && root._trApi) { root._trApi.set(windowSpec); } }
  };

  if (document.readyState !== 'loading') { initAll(); }
  else { document.addEventListener('DOMContentLoaded', function () { initAll(); }); }
})();
