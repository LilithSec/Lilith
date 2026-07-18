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
  function pad(n) { return (n < 10 ? '0' : '') + n; }

  function clampInt(v, lo, hi) {
    v = parseInt(v, 10);
    if (isNaN(v)) { return lo; }
    return Math.max(lo, Math.min(hi, v));
  }

  function initOne(root) {
    if (root.dataset.trReady) { return; }   // idempotent
    root.dataset.trReady = '1';

    var q = function (role) { return root.querySelector('[data-role="' + role + '"]'); };
    var preset  = q('preset');
    var custom  = q('custom');
    var minutes = q('minutes');
    var startEl = q('start');
    var endEl   = q('end');
    if (!preset || !minutes || !startEl || !endEl) { return; }
    var form = root.closest('form');

    // def is the whole-day time a bound falls back to when its time is left
    // unset: the start of the day for From, the end of it for To.
    var parts = {
      start: { date: q('start-date'), hour: q('start-hour'), min: q('start-min'), def: [0, 0] },
      end:   { date: q('end-date'),   hour: q('end-hour'),   min: q('end-min'),   def: [23, 59] }
    };

    function isCustom() { return preset.value === 'custom'; }

    // Show/hide the custom range and keep only the active mode's params live, so
    // the reader picks an explicit range over go_back_minutes accordingly.
    function apply() {
      if (custom) { custom.style.display = isCustom() ? '' : 'none'; }
      minutes.disabled = isCustom();
      startEl.disabled = !isCustom();
      endEl.disabled   = !isCustom();
      if (!isCustom()) { minutes.value = preset.value; }
    }

    // 'YYYY-MM-DD HH:MM' from a {date,hour,min} group, or '' with no date. An
    // unset time falls back to the group's default (From 00:00, To 23:59).
    function compose(g) {
      if (!g || !g.date || !g.date.value) { return ''; }
      var h = g.hour.value === '' ? g.def[0] : clampInt(g.hour.value, 0, 23);
      var m = g.min.value === '' ? g.def[1] : clampInt(g.min.value, 0, 59);
      return g.date.value + ' ' + pad(h) + ':' + pad(m);
    }

    // Seed a {date,hour,min} group from a 'YYYY-MM-DD[ T]HH:MM' string.
    function seed(g, val) {
      var m = /^(\d{4}-\d{2}-\d{2})[ T](\d{1,2}):(\d{2})/.exec(val || '');
      if (m && g && g.date) { g.date.value = m[1]; g.hour.value = parseInt(m[2], 10); g.min.value = parseInt(m[3], 10); }
    }

    // When a date is picked, surface the group's default time (only if the user
    // hasn't set one) so the whole-day bound is visible and still editable.
    function wireDate(g) {
      if (!g.date) { return; }
      g.date.addEventListener('change', function () {
        if (!g.date.value) { return; }
        if (g.hour.value === '') { g.hour.value = g.def[0]; }
        if (g.min.value === '') { g.min.value = g.def[1]; }
      });
    }
    wireDate(parts.start);
    wireDate(parts.end);

    preset.addEventListener('change', apply);
    if (form) {
      form.addEventListener('submit', function () {
        if (isCustom()) { startEl.value = compose(parts.start); endEl.value = compose(parts.end); }
      });
    }

    // Open in Custom when an absolute bound is already present; seed its fields.
    if (startEl.value || endEl.value) {
      preset.value = 'custom';
      seed(parts.start, startEl.value);
      seed(parts.end, endEl.value);
    }
    apply();
  }

  function initAll(scope) {
    (scope || document).querySelectorAll('.time-range').forEach(initOne);
  }

  window.LilithTimeRange = { init: initOne, initAll: initAll };

  if (document.readyState !== 'loading') { initAll(); }
  else { document.addEventListener('DOMContentLoaded', function () { initAll(); }); }
})();
