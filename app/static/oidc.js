function oidcLoginError(reason) {
  return ({email_missing:'Der Anbieter liefert keine E-Mail-Adresse. In Authentik den Scope email und dessen Zuordnung prüfen.',email_unverified:'Der Anbieter bestätigt die E-Mail-Adresse nicht. Die optionale E-Mail-Bestätigung in den OIDC-Einstellungen ausschalten oder beim Anbieter einrichten.',existing_account:'Dieses Konto besteht bereits. Zuerst lokal anmelden und unter Konto mit OIDC verknüpfen.',registration_disabled:'Für dieses neue Konto wird eine Einladung oder eine aktivierte Registrierung benötigt.',invalid_client:'Authentik lehnt Client-ID oder Client-Secret ab. Die OIDC-Zugangsdaten prüfen.',access_denied:'Die Anmeldung wurde beim Anbieter abgebrochen oder abgelehnt.',invalid_grant:'Authentik hat den Anmeldungscode abgelehnt. Redirect-URI und PKCE prüfen.',network:'Der OIDC-Anbieter ist vom DMS aus nicht erreichbar oder sein TLS-Zertifikat wird nicht akzeptiert.',account_disabled:'Das zugeordnete DMS-Konto ist gesperrt.',token:'OIDC-Tokenprüfung fehlgeschlagen. Im Adminbereich die OIDC-Anmeldung testen.',configuration:'OIDC ist nicht korrekt konfiguriert. Im Adminbereich die Konfiguration prüfen.'})[reason] || 'OIDC-Anmeldung fehlgeschlagen. Im Adminbereich die Konfiguration und Anmeldung testen. Dieselbe Domain verwenden und Cookies zulassen.';
}

function addOidcTests() {
  const form = document.querySelector('form[data-form="auth-config"]');
  form.querySelector('.modal-error').insertAdjacentHTML('beforebegin', `<section class="oidc-tests"><h3>Verbindung und Anmeldung prüfen</h3><p>Die Konfigurationsprüfung verwendet die aktuellen Eingaben. Der Anmeldetest verwendet die gespeicherte, aktivierte Konfiguration. Ihre Admin-Sitzung bleibt erhalten; der Test legt kein Konto an und verknüpft keines.</p><div class="form-actions"><button type="button" class="btn" data-oidc-action="config">Konfiguration prüfen</button><button type="button" class="btn" data-oidc-action="signin">Anmeldung testen</button></div><div id="oidc-test-report" aria-live="polite"></div></section>`);
}

function displayOidcReport(result) {
  const target = document.getElementById('oidc-test-report');
  if (!target) return;
  const labels = {success:'Erfolgreich',warning:'Hinweis',error:'Fehler',pending:'Noch offen'};
  target.innerHTML = result.checks.map(c => `<div class="oidc-check oidc-${e(c.status)}"><div><strong>${e(c.label)}</strong><span class="badge ${c.status==='success'?'':'gray'}">${e(labels[c.status]||'Hinweis')}</span></div><p>${e(c.message)}</p></div>`).join('');
}

async function showOidcTestResult() {
  const url = new URL(location.href); url.searchParams.delete('oidc_test'); history.replaceState({}, '', url.pathname+url.search+url.hash);
  await navigate('admin');
  await authModal('oidc');
  try { displayOidcReport(await api('/api/admin/auth/oidc/test/result')); }
  catch (err) { displayOidcReport({checks:[{label:'Anmeldetest',status:'error',message:err.message}]}); }
}

document.addEventListener('click', async event => {
  const btn = event.target.closest('[data-oidc-action]');
  if (!btn) return;
  const buttons = [...btn.closest('form').querySelectorAll('button')];
  buttons.forEach(b => b.disabled = true);
  try {
    if (btn.dataset.oidcAction === 'config') {
      const form = btn.closest('form');
      const config = Object.fromEntries(new FormData(form));
      delete config.kind; delete config.enabled;
      config.require_verified_email = form.elements.require_verified_email.checked;
      displayOidcReport({checks:[{label:'Verbindungstest läuft',status:'pending',message:'Der DMS-Server prüft Discovery und Signaturschlüssel …'}]});
      displayOidcReport(await api('/api/admin/auth/oidc/test', {method:'POST',body:{config,browser_origin:location.origin}}));
    } else {
      const result = await api('/api/admin/auth/oidc/test/start', {method:'POST',body:{}});
      location.assign(result.url);
    }
  } catch (err) { displayOidcReport({checks:[{label:'Test konnte nicht abgeschlossen werden',status:'error',message:err.message}]}); }
  finally { buttons.forEach(b => b.disabled = false); }
});
