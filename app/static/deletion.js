function documentRowActions(doc, compact) {
  if (doc.status === 'purging') return '';
  const open = `<button class="icon-button" data-open-doc="${e(doc.id)}" aria-label="Dokument öffnen">${icon('chevron')}</button>`;
  if (compact || !can('editor') || doc.can_edit === false) return open;
  return `<div class="document-row-actions">${open}${doc.deleted_at ?
    `<button class="icon-button" data-delete-restore="${e(doc.id)}" aria-label="Dokument wiederherstellen" title="Wiederherstellen">${icon('refresh')}</button>${can('manager') ? `<button class="icon-button delete-document" data-purge-doc="${e(doc.id)}" aria-label="Dokument endgültig löschen" title="Endgültig löschen">${icon('trash')}</button>` : ''}` :
    `<button class="icon-button delete-document" data-delete-doc="${e(doc.id)}" aria-label="Dokument löschen" title="In den Papierkorb verschieben" ${doc.status === 'processing' ? 'disabled' : ''}>${icon('trash')}</button>`}</div>`;
}

document.addEventListener('click', async event => {
  const target = event.target.closest('[data-delete-doc],[data-delete-restore],[data-purge-doc],[data-delete-confirm]');
  if (!target) return;
  event.stopImmediatePropagation();
  try {
    if (target.dataset.deleteDoc) {
      confirmModal('Dokument löschen', 'Das Dokument wird in den Papierkorb verschoben. Sie können es dort wiederherstellen.', 'trash', target.dataset.deleteDoc);
      return;
    }
    if (target.dataset.purgeDoc) {
      const doc = state.items?.find(row => row.id === target.dataset.purgeDoc) || state.doc;
      modal('Dokument endgültig löschen', `<div class="modal-body"><p><strong>${e(doc?.filename || 'Dieses Dokument')}</strong> wird mit allen Versionen, OCR-Texten, Notizen, PDF-Markierungen, Prüfungen und Freigabelinks gelöscht.</p><p>Diese Aktion kann nicht rückgängig gemacht werden.</p><div class="form-actions"><button class="btn" data-action="close-modal">Abbrechen</button><button class="btn danger" data-delete-confirm="${e(target.dataset.purgeDoc)}">Endgültig löschen</button></div></div>`);
      return;
    }
    target.disabled = true;
    if (target.dataset.deleteRestore) {
      await api(base() + '/documents/' + target.dataset.deleteRestore + '/restore', {method: 'POST'});
      toast('Dokument wiederhergestellt.');
    } else {
      await api(base() + '/documents/' + target.dataset.deleteConfirm + '/purge', {method: 'POST', body: {confirmed: true}});
      toast('Endgültiges Löschen gestartet.');
    }
    $('#modal').close(); await refresh();
  } catch (error) { toast(error.message, true); }
  finally { target.disabled = false; }
}, true);

let deletionRefreshing = false;
setInterval(async () => {
  if (deletionRefreshing || !state.me || state.page !== 'trash' || $('#modal').open || !state.items?.some(doc => doc.status === 'purging')) return;
  deletionRefreshing = true;
  try { await refresh(); } catch {} finally { deletionRefreshing = false; }
}, 5000);
