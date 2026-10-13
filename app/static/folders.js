const FOLDER_SCHEMAS = [
 ['year-sender', 'Jahr → Absender', '{year}/{sender}'],
 ['sender-year', 'Absender → Jahr', '{sender}/{year}'],
 ['type-year-month', 'Dokumenttyp → Jahr → Monat', '{doc_type}/{year}/{month}'],
];
function folderTemplateFields(rule){
 return selectField('Ordnerstruktur','folder_schema',[['','Eigene Vorlage / keine Unterordner'],...FOLDER_SCHEMAS.map(([key,label])=>[key,label])],FOLDER_SCHEMAS.find(row=>row[2]===rule.folder_template)?.[0]||'')+
 field('Ordner-Vorlage (optional)','folder_template',rule.folder_template||'','text','maxlength="700" placeholder="Rechnungen/{year}/{sender}" autocomplete="off" spellcheck="false"');
}
function folderCards(folders){
 return `<div class="folder-grid">${folders.map(f=>{const children=state.folders.filter(child=>child.parent_id===f.id).length;return `<div class="folder-card"><button class="btn text" data-folder="${f.id}" aria-label="Ordner ${e(f.name)} öffnen">${icon('folder')}</button><strong>${e(f.display_name||f.name)}</strong><p>${f.total_count??f.count} ${(f.total_count??f.count)===1?'Dokument':'Dokumente'}${children?` · ${children} Unterordner`:''}</p><div class="form-actions"><button class="btn text small" data-folder="${f.id}">Öffnen ${icon('chevron')}</button>${can('owner')?`<button class="btn small" data-feature-action="access" data-kind="folders" data-id="${f.id}">${icon('shield')}Zugriff</button>`:''}${can('manager')?`<button class="icon-button" data-remove-folder="${f.id}" aria-label="Ordner löschen">${icon('trash')}</button>`:''}</div></div>`;}).join('')}</div>`;
}
function renderFolderOverview(){
 return heading('Ordnung, die zu Ihnen passt.','Ordner und Unterordner nach Jahr, Absender oder Dokumenttyp.',can('manager')?button('new-folder','Ordner erstellen','plus','primary'):'')+
 folderCards(state.folders.filter(f=>!f.parent_id))+`<div class="callout">${icon('info')}Automatische Regeln können Unterordner aus Dokumentangaben anlegen. Zugriffsbeschränkungen übergeordneter Ordner gelten auch für ihre Unterordner.</div>`;
}
function folderChildrenBar(){
 if(state.page!=='documents'||!state.folder)return '';
 const selected=state.folders.find(f=>f.id===state.folder);if(!selected)return '';
 const ancestors=[];let current=selected;
 while(current&&ancestors.length<8){ancestors.unshift(current);current=state.folders.find(f=>f.id===current.parent_id);}
 const children=state.folders.filter(f=>f.parent_id===selected.id);
 return `<nav class="folder-breadcrumbs" aria-label="Ordnerpfad"><button class="btn text small" data-page="folders">${icon('folder')} Alle Ordner</button>${ancestors.map(f=>`${icon('chevron')}<button class="btn text small" data-folder="${f.id}" ${f.id===selected.id?'aria-current="location"':''}>${e(f.display_name||f.name)}</button>`).join('')}${can('manager')?button('new-folder','Unterordner erstellen','plus','small'):''}</nav>${children.length?`<h2 class="subfolder-heading">Unterordner</h2>${folderCards(children)}`:''}`;
}
function folderModal(){
 formModal('Ordner erstellen','folder',field('Ordnername','name','','text','required maxlength="150"')+
 selectField('Übergeordneter Ordner','parent_id',[['','Hauptebene'],...state.folders.map(f=>[f.id,f.name])],state.page==='documents'?state.folder||'':''));
}
