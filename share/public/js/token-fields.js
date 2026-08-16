/*
 * Shared token filter fields, used by /search and /logs: upgrade a page's
 * multi-valued filter <select multiple>s into type-to-add token fields with a
 * removable chip per value, and offer a field the values that actually occur,
 * fetched from the page's values endpoint when it is focused.
 *
 * Markup contract: a token field is a <select multiple> with class
 * .token-filter-field. One whose dropdown should offer the occurring values
 * names its column in data-column. One whose vocabulary is fixed carries
 * data-fixed="1" and its whole option set in the markup -- free typing is off
 * for those, since a value outside the set would die or match nothing.
 *
 * This is enhancement only: Tom Select keeps the original <select multiple> as
 * the form control and just drives it, so the page submits the same one
 * parameter per value either way. If the vendored file is missing the fields
 * stay the plain multi-selects they are in the markup -- usable, if only for
 * dropping values rather than adding them -- which is why nothing else here
 * depends on TomSelect being defined.
 */
window.LilithTokenFields = (function () {

// What init() was handed: the values endpoint and the page's query builder.
var _opts = {};

// Fetch a field's values and hand them to Tom Select. A column the values
// endpoint cannot group by answers 400, and an unreachable database answers
// 400 as well; either way the field is left as the free text one it already
// is, since a filter that cannot suggest is not a filter that cannot be typed.
function fetchValueSuggestions(selectEl, callback) {
  fetch(_opts.valuesUrl + '?' + selectEl.dataset.suggestQuery)
    .then(function(response) { return response.ok ? response.json() : { values: [] }; })
    .then(function(data) {
      callback((data.values || []).map(function(row) {
        return { value: String(row.value), text: String(row.value), count: row.count };
      }));
    })
    .catch(function() { callback([]); });
}

// Load a field's values if what it holds is not already the right list. Called
// on focus, so a field is only ever fetched for once it is used. The page's
// valuesQuery(selectEl) builds the query string, which doubles as the cache
// key for what the field last loaded: change the table/source or the window
// and it no longer matches, so the next focus fetches again. clearOptions
// keeps the values currently selected, so refetching never drops a chip.
function loadValueSuggestions(selectEl) {
  if (!selectEl.dataset.column || !selectEl.tomselect) { return; }

  var query = _opts.valuesQuery(selectEl);
  if (selectEl.dataset.suggestQuery === query) { return; }
  selectEl.dataset.suggestQuery = query;

  selectEl.tomselect.clearOptions();
  selectEl.tomselect.load('');
}

return {
  // Upgrade every .token-filter-field on the page. opts:
  //   valuesUrl:   the values endpoint, e.g. '/api/search/values'
  //   valuesQuery: function(selectEl) -> the endpoint's query string for that
  //                field (its column plus whatever scopes the page's results)
  init: function(opts) {
    _opts = opts || {};
    if (!window.TomSelect) { return; }

    document.querySelectorAll('select.token-filter-field').forEach(function(selectEl) {
      // A field whose vocabulary is fixed (data-fixed, e.g. the shodan known
      // states) offers exactly its markup options: free typing is off, since
      // anything outside the set would die or match nothing.
      var fixedField = selectEl.dataset.fixed === '1';
      new TomSelect(selectEl, {
        plugins:     ['remove_button'],
        placeholder: 'any',
        create:      !fixedField,
        // per-option data riding along in the markup, e.g. a fixed value's gloss
        dataAttr:    'data-data',
        // The dropdown offers the values that actually occur (see
        // loadValueSuggestions), which is a fetch on focus rather than one per
        // keystroke: the whole list arrives at once and Tom Select filters it
        // here. shouldLoad therefore refuses the per-keystroke load Tom Select
        // would otherwise do.
        shouldLoad: function() { return false; },
        load:       function(query, callback) { fetchValueSuggestions(selectEl, callback); },
        onFocus:    function() { loadValueSuggestions(selectEl); },
        // the fetched values arrive most common first, which is the order to
        // show them in when nothing has been typed to rank them by; a fixed
        // field keeps its markup order, which is written meaningful-first
        sortField:  fixedField ? [ { field: '$order' } ] : [ { field: '$score' }, { field: '$order' } ],
        // a column with more values than the dropdown's default cap is exactly
        // one worth scrolling rather than silently truncating
        maxOptions: null,
        render: {
          option: function(data) {
            var row = document.createElement('div');
            row.textContent = data.text;
            // the annotation beside a value: how often it occurs (suggested
            // values) or what it means (fixed ones)
            var note = data.count !== undefined ? data.count : data.desc;
            if (note !== undefined) {
              var noteEl = document.createElement('span');
              noteEl.className   = 'text-muted small ms-2';
              noteEl.textContent = note;
              row.appendChild(noteEl);
            }
            return row;
          }
        },
        // a value typed but not entered would otherwise be dropped on the floor
        // when the search is submitted, silently running a different search than
        // the one on screen
        createOnBlur: true,
        // comma is how these fields took several values before they were tokens,
        // and how a pasted list is written
        delimiter:   ',',
        // a removed value should leave the dropdown with it rather than hang
        // around as a suggestion
        persist:     false
      });
    });
  },

  // Make a filter field hold one value and nothing else. The fields are token
  // fields, so what a click-to-filter cell wants is a replacement rather than
  // an addition: clicking a second instance would otherwise widen the search to
  // both rather than narrow it to the one clicked. Handles the field either as
  // Tom Select left it or as the plain <select multiple> it is without.
  setValue: function(fieldEl, value) {
    if (fieldEl.tomselect) {
      fieldEl.tomselect.clear(true);
      fieldEl.tomselect.addOption({ value: value, text: value });
      fieldEl.tomselect.addItem(value, true);
      return;
    }

    fieldEl.innerHTML = '';
    var option = document.createElement('option');
    option.value = value;
    option.textContent = value;
    option.selected = true;
    fieldEl.appendChild(option);
  }
};
})();
