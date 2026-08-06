/*
 * Client-side column sorting for a rendered results table.
 *
 * LilithTable.initSort(tableEl) makes every <th> in the table's thead a sort
 * toggle: first click sorts ascending, clicking the same column again reverses.
 * Numeric-looking cells compare as numbers, everything else with localeCompare.
 * The active column's header gets a ▲ / ▼ suffix.
 *
 * This sorts only the rows currently in the DOM — it is a view convenience on
 * top of the server's own order_by, not a replacement for it.
 */
(function () {

  function initSort(table) {
    if (!table) { return; }
    var thead = table.querySelector('thead');
    var tbody = table.querySelector('tbody');
    if (!thead || !tbody) { return; }
    var headerCells = Array.prototype.slice.call(thead.querySelectorAll('th'));
    var sortCol = -1, sortAsc = true;

    headerCells.forEach(function (headerCell) {
      headerCell.dataset.origText = headerCell.textContent;
      headerCell.style.cursor = 'pointer';
      headerCell.style.userSelect = 'none';
    });

    headerCells.forEach(function (headerCell, idx) {
      headerCell.addEventListener('click', function () {
        if (sortCol === idx) {
          sortAsc = !sortAsc;
        } else {
          sortCol = idx;
          sortAsc = true;
        }
        headerCells.forEach(function (otherHeaderCell) { otherHeaderCell.textContent = otherHeaderCell.dataset.origText; });
        headerCell.textContent = headerCell.dataset.origText + (sortAsc ? ' ▲' : ' ▼');

        var rows = Array.prototype.slice.call(tbody.querySelectorAll('tr'));
        rows.sort(function (a, b) {
          var aText = a.cells[idx] ? a.cells[idx].textContent.trim() : '';
          var bText = b.cells[idx] ? b.cells[idx].textContent.trim() : '';
          var aNum = parseFloat(aText), bNum = parseFloat(bText);
          var cmp = (!isNaN(aNum) && !isNaN(bNum)) ? aNum - bNum : aText.localeCompare(bText);
          return sortAsc ? cmp : -cmp;
        });
        rows.forEach(function (row) { tbody.appendChild(row); });
      });
    });
  }

  window.LilithTable = { initSort: initSort };
})();
