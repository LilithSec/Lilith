/*
 * The /escalation page: the escalation target table and its add/edit/test/
 * delete modal. The per-type config form is generated from each type's own
 * field spec, so a newly installed escalation type needs no change here.
 *
 * The page publishes window.LilithEscalation.{targets,types} -- the target
 * rows and the installed type specs -- which this reads at DOMContentLoaded.
 *
 * Requires lilith-util.js.
 */
(function () {
document.addEventListener('DOMContentLoaded', function() {
  var util        = window.LilithUtil;
  var boot        = window.LilithEscalation || {};
  var ESC_TARGETS = boot.targets || [];
  var ESC_TYPES   = boot.types || [];
  var targetModal = new bootstrap.Modal(document.getElementById('target-modal'));
  var testModal   = new bootstrap.Modal(document.getElementById('test-result-modal'));
  var typeEl      = document.getElementById('target-type');
  var fieldsEl    = document.getElementById('target-config-fields');
  var statusEl    = document.getElementById('esc-action-status');

  function showStatus(message, succeeded) { util.showStatus(statusEl, message, succeeded); }

  function typeInfo(typeName) { return util.findBy(ESC_TYPES, 'type', typeName); }

  function findTarget(targetId) { return util.findById(ESC_TARGETS, targetId); }

  // populate the type select
  ESC_TYPES.forEach(function(escType) {
    var option = document.createElement('option');
    option.value = escType.type;
    option.textContent = escType.type;
    typeEl.appendChild(option);
  });

  // Build a repeatable "list" config field. Returns the container element,
  // which carries the data-config-name/type dataset. Each value is a row
  // tagged data-config-list-row; a field with a "columns" spec renders one
  // data-config-list-col input per column, otherwise a single
  // data-config-list-item input. An empty spare row and an add button let
  // the user grow the list.
  function buildListField(field, values) {
    var container = document.createElement('div');
    var rows = document.createElement('div');
    rows.className = 'd-flex flex-column gap-2';
    container.appendChild(rows);

    function addRow(value) {
      var row = document.createElement('div');
      row.className = 'input-group input-group-sm';
      row.dataset.configListRow = '1';
      if (field.columns) {
        field.columns.forEach(function(column) {
          var input = document.createElement('input');
          input.type = 'text';
          input.className = 'form-control';
          input.placeholder = column.placeholder || column.name;
          input.dataset.configListCol = column.name;
          if (value && value[column.name] !== undefined && value[column.name] !== null) { input.value = value[column.name]; }
          row.appendChild(input);
        });
      } else {
        var singleInput = document.createElement('input');
        singleInput.type = 'text';
        singleInput.className = 'form-control';
        singleInput.dataset.configListItem = '1';
        if (typeof value === 'string') { singleInput.value = value; }
        row.appendChild(singleInput);
      }
      var removeBtn = document.createElement('button');
      removeBtn.type = 'button';
      removeBtn.className = 'btn btn-outline-danger';
      removeBtn.textContent = '✕';
      removeBtn.addEventListener('click', function() { rows.removeChild(row); });
      row.appendChild(removeBtn);
      rows.appendChild(row);
    }

    (Array.isArray(values) ? values : []).forEach(addRow);
    addRow();   // one empty spare row to type into

    var addBtn = document.createElement('button');
    addBtn.type = 'button';
    addBtn.className = 'btn btn-sm btn-outline-secondary mt-2';
    addBtn.textContent = '+ Add';
    addBtn.addEventListener('click', function() { addRow(); });
    container.appendChild(addBtn);

    return container;
  }

  // Build the config inputs for a type from its config_fields spec. For an
  // edit, current values are filled in; a secret that is already set shows a
  // "(unchanged)" placeholder and an empty value, which the server treats as
  // "keep what is stored".
  function buildConfigForm(typeName, target) {
    fieldsEl.innerHTML = '';
    var info = typeInfo(typeName);
    document.getElementById('target-type-desc').textContent = info ? info.description : '';
    if (!info) { return; }
    var config     = (target && target.config)      || {};
    var secretsSet = (target && target.secrets_set) || [];
    info.fields.forEach(function(field) {
      var fieldColumn = document.createElement('div');
      fieldColumn.className = 'col-md-6';
      var label = document.createElement('label');
      label.className = 'form-label small text-muted mb-1';
      label.textContent = field.label + (field.required ? ' *' : '');
      fieldColumn.appendChild(label);
      var input;
      if (field.type === 'boolean') {
        var checkWrap = document.createElement('div');
        checkWrap.className = 'form-check';
        input = document.createElement('input');
        input.type = 'checkbox';
        input.className = 'form-check-input';
        input.checked = config[field.name] !== undefined ? !!config[field.name] : !!field.default;
        checkWrap.appendChild(input);
        fieldColumn.appendChild(checkWrap);
      } else if (field.type === 'enum') {
        input = document.createElement('select');
        input.className = 'form-select form-select-sm';
        (field.options || []).forEach(function(optionValue) {
          var option = document.createElement('option');
          option.value = optionValue;
          option.textContent = optionValue;
          input.appendChild(option);
        });
        var currentValue = (config[field.name] !== undefined && config[field.name] !== null) ? config[field.name]
                : (field.default !== undefined && field.default !== null ? field.default : '');
        if (currentValue !== '') { input.value = currentValue; }
        fieldColumn.appendChild(input);
      } else if (field.type === 'list') {
        fieldColumn.className = 'col-12';
        // a new target has no stored value, so seed the rows from the field
        // default; an existing target uses its own value, even when empty
        var listValues = (config[field.name] !== undefined) ? config[field.name] : field.default;
        input = buildListField(field, listValues);
        fieldColumn.appendChild(input);
      } else {
        input = document.createElement('input');
        input.type = (field.type === 'secret') ? 'password' : 'text';
        if (field.type === 'integer') { input.inputMode = 'numeric'; }
        input.className = 'form-control form-control-sm';
        if (field.type === 'secret') {
          input.autocomplete = 'new-password';
          if (secretsSet.indexOf(field.name) !== -1) { input.placeholder = '(unchanged)'; }
        } else if (config[field.name] !== undefined && config[field.name] !== null) {
          input.value = config[field.name];
        } else if (field.default !== undefined && field.default !== null) {
          input.placeholder = 'default: ' + field.default;
        }
        fieldColumn.appendChild(input);
      }
      if (field.help) {
        var helpText = document.createElement('div');
        helpText.className = 'form-text small';
        helpText.textContent = field.help;
        fieldColumn.appendChild(helpText);
      }
      input.dataset.configName = field.name;
      input.dataset.configType = field.type;
      fieldsEl.appendChild(fieldColumn);
    });
  }

  typeEl.addEventListener('change', function() {
    buildConfigForm(this.value, null);
  });

  function openModal(target) {
    document.getElementById('target-error').style.display = 'none';
    document.getElementById('target-id').value          = target ? target.id : '';
    document.getElementById('target-name').value        = target ? target.name : '';
    document.getElementById('target-description').value = target ? (target.description || '') : '';
    document.getElementById('target-enabled').checked   = target ? !!target.enabled : true;
    document.getElementById('target-modal-title').textContent
      = target ? ('Edit Escalation Target — ' + target.name) : 'Add Escalation Target';
    if (target) { typeEl.value = target.type; }
    else if (ESC_TYPES.length) { typeEl.value = ESC_TYPES[0].type; }
    typeEl.disabled = !!target;
    buildConfigForm(typeEl.value, target);
    targetModal.show();
  }

  document.getElementById('target-add-btn').addEventListener('click', function() {
    openModal(null);
  });
  document.querySelectorAll('.target-edit-btn').forEach(function(editButton) {
    editButton.addEventListener('click', function() {
      openModal(findTarget(this.dataset.targetId));
    });
  });

  document.getElementById('target-save-btn').addEventListener('click', function() {
    var errorEl = document.getElementById('target-error');
    errorEl.style.display = 'none';
    var config = {};
    fieldsEl.querySelectorAll('[data-config-name]').forEach(function(input) {
      var fieldName = input.dataset.configName;
      if (input.dataset.configType === 'boolean') {
        config[fieldName] = input.checked ? 1 : 0;
      } else if (input.dataset.configType === 'list') {
        var items = [];
        input.querySelectorAll('[data-config-list-row]').forEach(function(row) {
          var columnInputs = row.querySelectorAll('[data-config-list-col]');
          if (columnInputs.length) {
            var rowObj = {}, hasValue = false;
            columnInputs.forEach(function(columnInput) {
              var value = columnInput.value.trim();
              rowObj[columnInput.dataset.configListCol] = value;
              if (value !== '') { hasValue = true; }
            });
            if (hasValue) { items.push(rowObj); }
          } else {
            var singleInput = row.querySelector('[data-config-list-item]');
            if (singleInput && singleInput.value.trim() !== '') { items.push(singleInput.value.trim()); }
          }
        });
        // always send the list, even when empty, so a cleared list is a
        // deliberate opt out rather than falling back to the field default
        config[fieldName] = items;
      } else if (input.value !== '') {
        config[fieldName] = input.value;
      }
    });
    var requestBody = {
      id:          document.getElementById('target-id').value,
      name:        document.getElementById('target-name').value.trim(),
      type:        typeEl.value,
      config:      config,
      description: document.getElementById('target-description').value,
      enabled:     document.getElementById('target-enabled').checked ? 1 : 0
    };
    util.postResult('/api/escalation/targets', requestBody)
      .then(function(result) {
        if (!result.ok || result.data.error) {
          errorEl.textContent = result.data.error || 'save failed';
          errorEl.style.display = '';
          return;
        }
        window.location.reload();
      })
      .catch(function(error) {
        errorEl.textContent = 'save failed: ' + error;
        errorEl.style.display = '';
      });
  });

  document.querySelectorAll('.target-delete-btn').forEach(function(deleteButton) {
    deleteButton.addEventListener('click', function() {
      var targetId = this.dataset.targetId;
      if (!window.confirm('Delete escalation target "' + this.dataset.targetName + '"?')) { return; }
      fetch('/api/escalation/targets/' + encodeURIComponent(targetId) + '/delete', { method: 'POST' })
        .then(util.unwrap)
        .then(function(result) {
          if (!result.ok || result.data.error) {
            showStatus(result.data.error || 'delete failed', false);
            return;
          }
          window.location.reload();
        })
        .catch(function(error) { showStatus('delete failed: ' + error, false); });
    });
  });

  document.querySelectorAll('.target-test-btn').forEach(function(testButton) {
    testButton.addEventListener('click', function() {
      var targetId = this.dataset.targetId;
      var target   = findTarget(targetId);
      document.getElementById('test-result-title').textContent
        = 'Test Escalation — ' + (target ? target.name : targetId);
      document.getElementById('test-result-loading').style.display = '';
      document.getElementById('test-result-content').style.display = 'none';
      testModal.show();
      fetch('/api/escalation/targets/' + encodeURIComponent(targetId) + '/test', { method: 'POST' })
        .then(util.unwrap)
        .then(function(result) {
          var errorEl     = document.getElementById('test-result-error');
          var payloadWrap = document.getElementById('test-result-payload-wrap');
          if (!result.ok || result.data.error) {
            errorEl.textContent = result.data.error || 'test failed';
            errorEl.style.display = '';
            payloadWrap.style.display = 'none';
          } else {
            errorEl.style.display = 'none';
            document.getElementById('test-result-payload').textContent
              = JSON.stringify(result.data.payload, null, 2);
            payloadWrap.style.display = '';
          }
          document.getElementById('test-result-loading').style.display = 'none';
          document.getElementById('test-result-content').style.display = '';
        })
        .catch(function(error) {
          var errorEl = document.getElementById('test-result-error');
          errorEl.textContent = 'test failed: ' + error;
          errorEl.style.display = '';
          document.getElementById('test-result-loading').style.display = 'none';
          document.getElementById('test-result-content').style.display = '';
        });
    });
  });
});
})();
