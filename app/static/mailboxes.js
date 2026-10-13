function renderMailboxes(mailboxes) {
  const active = mailboxes.filter(mailbox => mailbox.enabled).length;
  return `<section class="card integration-card mailboxes-card">
    <div class="integration-logo">${icon('mail')}</div><h2>E-Mail-Import</h2>
    <p>Verbinden Sie mehrere Postfächer. Filter, Zugangsdaten und Importhistorie werden je Postfach verwaltet.</p>
    <span class="badge ${active ? '' : 'gray'}">${mailboxes.length ? `${active} von ${mailboxes.length} aktiv` : 'Keine Postfächer'}</span>
    <div class="mailbox-list">${mailboxes.map(mailbox => `<article class="mailbox-item">
      <div class="mailbox-title"><strong>${e(mailbox.name)}</strong><span class="badge ${mailbox.enabled ? '' : 'gray'}">${mailbox.enabled ? 'Aktiv' : 'Pausiert'}</span></div>
      <p class="muted">${e(mailbox.config.username)} · ${e(mailbox.config.host)}<br>${e(mailbox.config.folder || 'INBOX')} · ${mailbox.config.attachment_filter === 'pdf' ? 'Nur PDF-Anhänge' : 'Unterstützte Anhänge'}</p>
      <p class="muted">${mailbox.last_run ? `Zuletzt: ${dateFormat(mailbox.last_run)} · ${e(mailbox.last_status || '')}` : 'Noch nicht geprüft'}</p>
      <div class="mailbox-actions"><button class="btn small" data-mailbox-edit="${e(mailbox.id)}">${icon('settings')}Bearbeiten</button>
      ${mailbox.enabled ? `<button class="btn small" data-mailbox-run="${e(mailbox.id)}">${icon('refresh')}Jetzt prüfen</button>` : ''}
      <button class="btn text small" data-mailbox-remove="${e(mailbox.id)}">Entfernen</button></div>
    </article>`).join('')}</div>
    <button class="btn" data-mailbox-add>${icon('plus')}Postfach hinzufügen</button>
  </section>`;
}

function mailboxModal(id) {
  const saved = state.integrations?.find(row => row.kind === 'imap' && row.id === id);
  const config = saved?.config || {};
  formModal(saved ? 'Postfach bearbeiten' : 'Postfach hinzufügen', 'mailbox',
    field('Name des Postfachs', 'name', saved?.name || '', 'text', 'required maxlength="150" placeholder="Zum Beispiel: Rechnungen"') +
    field('IMAP-Server', 'host', config.host || '', 'text', 'required placeholder="imap.example.org"') +
    field('Port (TLS)', 'port', config.port || 993, 'number', 'required min="1" max="65535"') +
    field('Benutzername', 'username', config.username || '', 'text', 'required autocomplete="off"') +
    field('Passwort / App-Passwort', 'password', config.password || '', 'password', 'required autocomplete="new-password"') +
    field('Postfachordner', 'folder', config.folder || 'INBOX') +
    selectField('E-Mail-Filter', 'attachment_filter', [['all', 'Alle E-Mails – unterstützte Anhänge'], ['pdf', 'Nur E-Mails mit PDF-Anhang']], config.attachment_filter || 'all') +
    '<p class="muted">Im PDF-Modus werden ausschließlich anhand ihres Inhalts geprüfte PDF-Anhänge übernommen. E-Mail-Texte werden nur bei passenden Nachrichten zusätzlich importiert.</p>' +
    `<label class="checkbox"><input name="import_body" type="checkbox" ${config.import_body ? 'checked' : ''}>E-Mail-Texte zusätzlich importieren</label>` +
    `<label class="checkbox"><input name="enabled" type="checkbox" ${saved ? saved.enabled ? 'checked' : '' : 'checked'}>Postfach automatisch prüfen</label>`,
    'Postfach speichern', 'Prüfung alle 5 Minuten. Nachrichten bleiben unverändert. Bereits verarbeitete E-Mails werden dauerhaft je Postfach gespeichert. Pausieren erhält die Importhistorie.');
  const form = $('#modal form');
  delete form.dataset.form;
  form.dataset.mailboxForm = id || '';
}

document.addEventListener('click', async event => {
  const target = event.target.closest('[data-mailbox-add],[data-mailbox-edit],[data-mailbox-run],[data-mailbox-remove],[data-mailbox-confirm]');
  if (!target) return;
  try {
    if (target.hasAttribute('data-mailbox-add')) return mailboxModal();
    if (target.dataset.mailboxEdit) return mailboxModal(target.dataset.mailboxEdit);
    if (target.dataset.mailboxRemove) {
      const saved = state.integrations.find(row => row.id === target.dataset.mailboxRemove);
      modal('Postfach entfernen', `<div class="modal-body"><p>${e(saved.name)} wird getrennt. Importierte Dokumente bleiben erhalten; die Importhistorie dieser Verbindung wird entfernt. Deaktivieren Sie stattdessen die automatische Prüfung, um die Verbindung nur zu pausieren.</p><div class="form-actions"><button class="btn" data-action="close-modal">Abbrechen</button><button class="btn danger" data-mailbox-confirm="${e(saved.id)}">Postfach entfernen</button></div></div>`);
      return;
    }
    target.disabled = true;
    const id = target.dataset.mailboxRun || target.dataset.mailboxConfirm;
    const result = await api(base() + '/mailboxes/' + id + (target.dataset.mailboxRun ? '/run' : ''), {method: target.dataset.mailboxRun ? 'POST' : 'DELETE'});
    if (target.dataset.mailboxRun) toast(result.status, result.status.includes('fehlgeschlagen'));
    else { $('#modal').close(); toast('Postfach entfernt.'); }
    await refresh();
  } catch (error) { toast(error.message, true); }
  finally { target.disabled = false; }
});

document.addEventListener('submit', async event => {
  const form = event.target;
  if (!form.hasAttribute('data-mailbox-form')) return;
  event.preventDefault();
  const submit = $('button[type="submit"],button:not([type])', form);
  submit.disabled = true;
  $('.modal-error', form).textContent = '';
  try {
    const config = Object.fromEntries(new FormData(form));
    const name = config.name;
    delete config.name; delete config.enabled;
    config.port = Number(config.port);
    config.import_body = form.elements.import_body.checked;
    const id = form.dataset.mailboxForm;
    await api(base() + '/mailboxes' + (id ? '/' + id : ''), {method: id ? 'PUT' : 'POST', body: {name, enabled: form.elements.enabled.checked, config}});
    $('#modal').close(); toast('Postfach gespeichert.'); await refresh();
  } catch (error) { $('.modal-error', form).textContent = error.message; }
  finally { submit.disabled = false; }
});
