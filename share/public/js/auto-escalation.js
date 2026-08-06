/*
 * The /auto_escalation page: the rule table, the visual match-tree builder
 * (nested ALL/ANY/NOT groups of field/op/value tests) with its raw-JSON
 * toggle, and the dry-run preview that never sends.
 *
 * The page publishes window.LilithAutoEscalation.{rules,targets,canManage} --
 * the rule rows, the escalation targets a rule may name, and whether editing
 * is permitted (auto_escalation_manage_enable). With canManage false the page
 * stays read only: view and preview.
 *
 * Requires lilith-util.js.
 */
(function () {
var AE_BOOT       = window.LilithAutoEscalation || {};
var AE_RULES      = AE_BOOT.rules || [];
var AE_TARGETS    = AE_BOOT.targets || [];
var AE_CAN_MANAGE = !!AE_BOOT.canManage;
document.addEventListener('DOMContentLoaded', function() {
  var util      = window.LilithUtil;
  var ruleModal = new bootstrap.Modal(document.getElementById('rule-modal'));
  var statusEl  = document.getElementById('ae-action-status');

  function status(message, isSuccess) { util.showStatus(statusEl, message, isSuccess); }

  function findRule(id) { return util.findById(AE_RULES, id); }

  // ---- Visual match builder ------------------------------------------------
  // The builder edits the same match tree the DSL uses. A group serializes to
  // {all:[...]} or {any:[...]}; a leaf to {field,op,value}; a set "not" toggle
  // wraps either in {not:...}. The DOM is the source of truth: serialize walks
  // it, and rebuild constructs it from a parsed match. An "Advanced (JSON)"
  // toggle swaps the builder for a raw textarea, syncing in both directions.
  var AE_OPS  = ['==','!=','>','>=','<','<=','regex','in','contains','exists'];
  var jsonMode = false;

  function createElement(tag, attributes, children) {
    var element = document.createElement(tag);
    if (attributes) { Object.keys(attributes).forEach(function(attrName){
      if (attrName === 'class') { element.className = attributes[attrName]; }
      else if (attrName === 'text') { element.textContent = attributes[attrName]; }
      else { element.setAttribute(attrName, attributes[attrName]); }
    }); }
    (children || []).forEach(function(child){ if (child) { element.appendChild(child); } });
    return element;
  }

  // numeric-looking strings become numbers so ==/in compare as intended
  function coerceValue(value) { return /^-?\d+(\.\d+)?$/.test(value) ? Number(value) : value; }

  function valueWidget(operator, value) {
    if (operator === 'exists') {
      var select = createElement('select', { class: 'form-select form-select-sm leaf-value', style: 'max-width:6rem' });
      ['true','false'].forEach(function(optionValue){ select.appendChild(createElement('option', { value: optionValue, text: optionValue })); });
      select.value = (value === false ? 'false' : 'true');
      return select;
    }
    var input = createElement('input', { type: 'text', class: 'form-control form-control-sm leaf-value', style: 'max-width:13rem' });
    if (operator === 'in') {
      input.placeholder = 'a, b, c';
      input.value = Array.isArray(value) ? value.join(', ') : (value == null ? '' : value);
    } else {
      input.placeholder = 'value';
      input.value = (value == null ? '' : value);
    }
    return input;
  }

  function negateControl(checked) {
    var checkbox = createElement('input', { type: 'checkbox', class: 'form-check-input mt-0 node-negate' });
    checkbox.checked = !!checked;
    return createElement('label', { class: 'small text-muted mb-0 d-inline-flex align-items-center gap-1' },
              [checkbox, document.createTextNode('not')]);
  }

  function makeLeaf(leaf) {
    leaf = leaf || { field: '', op: '==', value: '' };
    var row = createElement('div', { class: 'leaf-node d-flex gap-1 align-items-center mb-1 flex-wrap' });
    row.dataset.kind = 'leaf';

    var field = createElement('input', { type: 'text', class: 'form-control form-control-sm leaf-field',
                              list: 'rule-field-list', placeholder: 'field', style: 'max-width:12rem' });
    field.value = leaf.field || '';

    var operatorSelect = createElement('select', { class: 'form-select form-select-sm leaf-op', style: 'max-width:6.5rem' });
    AE_OPS.forEach(function(operator){ var option = createElement('option', { value: operator, text: operator }); if (operator === leaf.op) { option.selected = true; } operatorSelect.appendChild(option); });

    var valueWrap = createElement('span', { class: 'leaf-value-wrap' }, [ valueWidget(leaf.op, leaf.value) ]);
    operatorSelect.addEventListener('change', function(){
      var currentValue = valueWrap.firstChild ? valueWrap.firstChild.value : '';
      valueWrap.innerHTML = '';
      valueWrap.appendChild(valueWidget(operatorSelect.value, currentValue));
    });

    var removeBtn = createElement('button', { type: 'button', class: 'btn btn-sm btn-outline-danger py-0 node-remove', text: '×' });
    removeBtn.addEventListener('click', function(){ row.remove(); });

    row.appendChild(negateControl(leaf.negate));
    row.appendChild(field);
    row.appendChild(operatorSelect);
    row.appendChild(valueWrap);
    row.appendChild(removeBtn);
    return row;
  }

  function makeGroup(group, isRoot) {
    group = group || { combinator: 'all', negate: false, children: [] };
    var groupEl = createElement('div', { class: 'group-node border-start border-2 border-secondary ps-2 mb-1' });
    groupEl.dataset.kind = 'group';

    var combinatorSelect = createElement('select', { class: 'form-select form-select-sm group-combinator', style: 'max-width:6rem' });
    [['all','ALL'],['any','ANY']].forEach(function(comboPair){ var option = createElement('option', { value: comboPair[0], text: comboPair[1] }); if (comboPair[0] === group.combinator) { option.selected = true; } combinatorSelect.appendChild(option); });

    var childrenEl = createElement('div', { class: 'group-children ms-1' });
    var addConditionBtn = createElement('button', { type: 'button', class: 'btn btn-sm btn-outline-secondary py-0', text: '+ condition' });
    var addGroupBtn  = createElement('button', { type: 'button', class: 'btn btn-sm btn-outline-secondary py-0', text: '+ group' });
    addConditionBtn.addEventListener('click', function(){ childrenEl.appendChild(makeLeaf(null)); });
    addGroupBtn.addEventListener('click', function(){ childrenEl.appendChild(makeGroup(null, false)); });

    var headerEl = createElement('div', { class: 'd-flex gap-1 align-items-center mb-1 flex-wrap' },
                  [ negateControl(group.negate), combinatorSelect, addConditionBtn, addGroupBtn ]);
    if (!isRoot) {
      var removeBtn = createElement('button', { type: 'button', class: 'btn btn-sm btn-outline-danger py-0 node-remove', text: '× group' });
      removeBtn.addEventListener('click', function(){ groupEl.remove(); });
      headerEl.appendChild(removeBtn);
    }

    groupEl.appendChild(headerEl);
    groupEl.appendChild(childrenEl);
    (group.children || []).forEach(function(childModel){
      childrenEl.appendChild(childModel.kind === 'group' ? makeGroup(childModel, false) : makeLeaf(childModel));
    });
    return groupEl;
  }

  function parseMatch(node) {
    var negate = false;
    while (node && typeof node === 'object' && node.not !== undefined) { negate = !negate; node = node.not; }
    if (node && (node.all || node.any)) {
      var combinator = node.all ? 'all' : 'any';
      return { kind: 'group', negate: negate, combinator: combinator, children: (node[combinator] || []).map(parseMatch) };
    }
    node = node || {};
    return { kind: 'leaf', negate: negate, field: node.field || '', op: node.op || '==', value: node.value };
  }

  function rebuildBuilder(match) {
    var model = parseMatch(match || {});
    if (model.kind !== 'group') { model = { kind: 'group', negate: false, combinator: 'all', children: [ model ] }; }
    var container = document.getElementById('rule-builder');
    container.innerHTML = '';
    container.appendChild(makeGroup(model, true));
  }

  function serializeNode(node) {
    var result, negate;
    if (node.dataset.kind === 'group') {
      var headEl = node.children[0];
      var combinator = headEl.querySelector('.group-combinator').value;
      negate = headEl.querySelector('.node-negate').checked;
      var children = [];
      Array.prototype.forEach.call(node.children[1].children, function(childNode){ children.push(serializeNode(childNode)); });
      result = {}; result[combinator] = children;
    } else {
      negate = node.querySelector('.node-negate').checked;
      var operator  = node.querySelector('.leaf-op').value;
      var valueEl = node.querySelector('.leaf-value');
      result = { field: node.querySelector('.leaf-field').value.trim(), op: operator };
      if (operator === 'exists') {
        result.value = (valueEl.value === 'true');
      } else if (operator === 'in') {
        result.value = valueEl.value.split(',').map(function(part){ return coerceValue(part.trim()); }).filter(function(part){ return part !== ''; });
      } else if (operator === '>' || operator === '>=' || operator === '<' || operator === '<=') {
        result.value = Number(valueEl.value);
      } else if (operator === 'regex' || operator === 'contains') {
        result.value = valueEl.value;
      } else {
        result.value = coerceValue(valueEl.value);
      }
    }
    if (negate) { result = { not: result }; }
    return result;
  }

  function serializeBuilder() {
    return serializeNode(document.getElementById('rule-builder').children[0]);
  }

  // the current match, from whichever editor is active; throws on bad JSON
  function buildMatch() {
    if (jsonMode) { return JSON.parse((document.getElementById('rule-match').value || '{}').trim() || '{}'); }
    return serializeBuilder();
  }

  document.getElementById('rule-json-toggle').addEventListener('click', function(){
    var errorEl   = document.getElementById('rule-error');
    var textarea  = document.getElementById('rule-match');
    var builderEl = document.getElementById('rule-builder');
    if (!jsonMode) {
      textarea.value = JSON.stringify(serializeBuilder(), null, 2);
      builderEl.style.display = 'none'; textarea.style.display = '';
      this.textContent = 'Visual builder';
      jsonMode = true;
    } else {
      var parsed;
      try { parsed = JSON.parse((textarea.value || '{}').trim() || '{}'); }
      catch (err) { errorEl.textContent = 'Advanced JSON is invalid: ' + err.message; errorEl.style.display = ''; return; }
      errorEl.style.display = 'none';
      rebuildBuilder(parsed);
      textarea.style.display = 'none'; builderEl.style.display = '';
      this.textContent = 'Advanced (JSON)';
      jsonMode = false;
    }
  });

  // datalist of known target names for the escalate_to input
  AE_TARGETS.forEach(function(target) {
    var option = document.createElement('option');
    option.value = target.name;
    document.getElementById('rule-target-list').appendChild(option);
  });

  function setDisabled(disabled) {
    ['rule-name','rule-priority','rule-enabled','rule-stop','rule-targets','rule-note','rule-description']
      .forEach(function(id){ document.getElementById(id).disabled = disabled; });
    document.querySelectorAll('.rule-table').forEach(function(element){ element.disabled = disabled; });
    // builder controls are rebuilt per open, so disable the fresh nodes here
    document.querySelectorAll('#rule-builder input, #rule-builder select, #rule-builder button')
      .forEach(function(element){ element.disabled = disabled; });
    document.getElementById('rule-match').readOnly = disabled;
  }

  function openModal(rule) {
    document.getElementById('rule-error').style.display = 'none';
    document.getElementById('rule-preview-results').style.display = 'none';
    document.getElementById('rule-preview-status').style.display = 'none';

    document.getElementById('rule-id').value       = rule ? rule.id : '';
    document.getElementById('rule-name').value     = rule ? rule.name : '';
    document.getElementById('rule-priority').value = rule ? rule.priority : 100;
    document.getElementById('rule-enabled').checked = rule ? !!rule.enabled : true;
    document.getElementById('rule-stop').checked    = rule ? !!rule.stop_on_match : false;
    document.getElementById('rule-description').value = rule ? (rule.description || '') : '';

    var tables = (rule && rule.tables) || ['suricata','sagan','cape'];
    document.querySelectorAll('.rule-table').forEach(function(element){
      element.checked = tables.indexOf(element.value) !== -1;
    });

    // decompose the stored rule: match tree, and merged escalate_to + first note
    var match = {}, targets = [], note = '';
    if (rule && rule.rule) {
      match = rule.rule.match || {};
      (rule.rule.actions || []).forEach(function(action){
        (action.escalate_to || []).forEach(function(target){ targets.push(target); });
        if (!note && action.note) { note = action.note; }
      });
    }

    // load the match into the visual builder, leaving JSON (advanced) mode
    jsonMode = false;
    document.getElementById('rule-match').style.display = 'none';
    document.getElementById('rule-builder').style.display = '';
    document.getElementById('rule-json-toggle').textContent = 'Advanced (JSON)';
    document.getElementById('rule-error').style.display = 'none';
    rebuildBuilder(match);

    document.getElementById('rule-targets').value = targets.join(', ');
    document.getElementById('rule-note').value    = note;
    document.getElementById('rule-preview-table').value =
      (tables.indexOf('suricata') !== -1) ? 'suricata' : tables[0] || 'suricata';

    setDisabled(!AE_CAN_MANAGE);
    document.getElementById('rule-modal-title').textContent =
      rule ? ((AE_CAN_MANAGE ? 'Edit' : 'View') + ' Rule — ' + rule.name) : 'Add Rule';
    ruleModal.show();
  }

  // Build the rule payload from the modal inputs. Returns {body} or {error}.
  function buildBody() {
    var match;
    try { match = buildMatch(); }
    catch (err) { return { error: 'Match is not valid JSON: ' + err.message }; }

    var targets = document.getElementById('rule-targets').value
      .split(',').map(function(part){ return part.trim(); }).filter(function(part){ return part !== ''; });

    var tables = [];
    document.querySelectorAll('.rule-table').forEach(function(element){ if (element.checked) { tables.push(element.value); } });

    var note = document.getElementById('rule-note').value.trim();
    var action = { escalate_to: targets };
    if (note !== '') { action.note = note; }

    return { body: {
      id:            document.getElementById('rule-id').value,
      name:          document.getElementById('rule-name').value.trim(),
      rule:          { match: match, actions: [ action ] },
      tables:        tables,
      priority:      document.getElementById('rule-priority').value.trim(),
      stop_on_match: document.getElementById('rule-stop').checked ? 1 : 0,
      enabled:       document.getElementById('rule-enabled').checked ? 1 : 0,
      description:   document.getElementById('rule-description').value.trim()
    } };
  }

  if (document.getElementById('rule-add-btn')) {
    document.getElementById('rule-add-btn').addEventListener('click', function(){ openModal(null); });
  }
  document.querySelectorAll('.rule-edit-btn').forEach(function(btn){
    btn.addEventListener('click', function(){ openModal(findRule(this.dataset.ruleId)); });
  });

  var saveBtn = document.getElementById('rule-save-btn');
  if (saveBtn) {
    saveBtn.addEventListener('click', function(){
      var errorEl = document.getElementById('rule-error');
      errorEl.style.display = 'none';
      var built = buildBody();
      if (built.error) { errorEl.textContent = built.error; errorEl.style.display = ''; return; }
      fetch('/api/auto_escalation/rules', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(built.body)
      })
        .then(util.unwrap)
        .then(function(result){
          if (!result.ok || result.data.error) {
            errorEl.textContent = result.data.error || 'save failed';
            errorEl.style.display = '';
            return;
          }
          window.location.reload();
        })
        .catch(function(err){ errorEl.textContent = 'save failed: ' + err; errorEl.style.display = ''; });
    });
  }

  document.querySelectorAll('.rule-delete-btn').forEach(function(btn){
    btn.addEventListener('click', function(){
      var id = this.dataset.ruleId;
      if (!window.confirm('Delete auto-escalation rule "' + this.dataset.ruleName + '"?')) { return; }
      fetch('/api/auto_escalation/rules/' + encodeURIComponent(id) + '/delete', { method: 'POST' })
        .then(util.unwrap)
        .then(function(result){
          if (!result.ok || result.data.error) { status(result.data.error || 'delete failed', false); return; }
          window.location.reload();
        })
        .catch(function(err){ status('delete failed: ' + err, false); });
    });
  });

  document.querySelectorAll('.rule-toggle').forEach(function(toggleInput){
    toggleInput.addEventListener('change', function(){
      var id = this.dataset.ruleId, wantEnabled = this.checked, checkbox = this;
      fetch('/api/auto_escalation/rules/' + encodeURIComponent(id) + '/toggle', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: wantEnabled ? 1 : 0 })
      })
        .then(util.unwrap)
        .then(function(result){
          if (!result.ok || result.data.error) { checkbox.checked = !wantEnabled; status(result.data.error || 'toggle failed', false); return; }
          status('rule ' + id + (wantEnabled ? ' enabled' : ' disabled'), true);
        })
        .catch(function(err){ checkbox.checked = !wantEnabled; status('toggle failed: ' + err, false); });
    });
  });

  document.getElementById('rule-preview-btn').addEventListener('click', function(){
    var errorEl           = document.getElementById('rule-error');
    var previewStatusEl   = document.getElementById('rule-preview-status');
    var previewResultsEl  = document.getElementById('rule-preview-results');
    var tbody             = document.getElementById('rule-preview-tbody');
    errorEl.style.display = 'none';
    previewResultsEl.style.display = 'none';

    var built = buildBody();
    if (built.error) { errorEl.textContent = built.error; errorEl.style.display = ''; return; }

    previewStatusEl.textContent = 'Running preview…';
    previewStatusEl.className = 'small mb-1 text-muted';
    previewStatusEl.style.display = '';

    fetch('/api/auto_escalation/preview', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        rule: built.body.rule,
        table: document.getElementById('rule-preview-table').value,
        go_back_minutes: document.getElementById('rule-preview-minutes').value.trim()
      })
    })
      .then(util.unwrap)
      .then(function(result){
        if (!result.ok || result.data.error) {
          previewStatusEl.textContent = result.data.error || 'preview failed';
          previewStatusEl.className = 'small mb-1 text-warning';
          return;
        }
        var data = result.data;
        var unknown = (data.unknown_targets && data.unknown_targets.length)
          ? ' — unknown targets: ' + data.unknown_targets.join(', ') : '';
        previewStatusEl.textContent = data.matched + ' of ' + data.scanned + ' recent ' + data.table
          + ' alerts would match' + unknown;
        previewStatusEl.className = 'small mb-1 ' + (data.matched ? 'text-success' : 'text-muted');
        tbody.innerHTML = '';
        (data.matches || []).forEach(function(match){
          var row = document.createElement('tr');
          [ match.id, match.timestamp || '', match.signature || match.classification || '', match.src_ip || '',
            match.dest_ip || '', (match.malscore == null ? '' : match.malscore) ].forEach(function(value){
            var cell = document.createElement('td'); cell.textContent = value; row.appendChild(cell);
          });
          tbody.appendChild(row);
        });
        previewResultsEl.style.display = (data.matches && data.matches.length) ? '' : 'none';
      })
      .catch(function(err){
        previewStatusEl.textContent = 'preview failed: ' + err;
        previewStatusEl.className = 'small mb-1 text-warning';
      });
  });
});
})();
