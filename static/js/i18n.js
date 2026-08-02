// Lightweight i18n: EN/PL/NO/DE. Cookie 'lang'. Applies to elements with data-i18n attribute.
(function(){
const DICT = {
  en: {
    'nav.logout':'Logout','nav.account':'Account Settings','nav.admin':'Admin Dashboard',
    'nav.messages':'Go to Messages',
    'login.title':'Login Page','login.identifier':'Identifier','login.password':'Password',
    'login.submit':'Login','login.reset':'Reset password by file','login.lang':'Language',
    'sb.messages':'Messages','sb.groups':'Groups','sb.create_group':'+ Create Group',
    'chat.placeholder':'Type a message...','chat.send':'Send','chat.select':'Select a contact or group to start chatting',
    'chat.settings':'Chat Settings','chat.delete_history':'Delete Chat History (yours only)',
    'chat.block':'Block User','chat.mute':'Mute User','chat.mute_calls':'Mute Calls',
    'chat.rename':'Rename User','chat.search':'Search in Conversation','chat.create_group':'Create Group',
    'chat.incoming':'Incoming call:',
    'admin.title':'Admin Dashboard','admin.manage_users':'Manage Users','admin.manage_perms':'Manage Permissions',
    'admin.reports':'Message Reports','admin.create_user':'Create User Account','admin.sys_msg':'Send System Message',
    'admin.ringtones':'Ringtones','admin.devices':'Device Registrations',
    'ringtones.title':'Ringtones','ringtones.upload':'Upload (MP3/WAV, max 30s)',
    'ringtones.set_default':'Set Default','ringtones.test':'Test','ringtones.delete':'Delete',
    'ringtones.default':'(default)','ringtones.builtin':'Built-in Beep'
  },
  pl: {
    'nav.logout':'Wyloguj','nav.account':'Ustawienia konta','nav.admin':'Panel admina',
    'nav.messages':'Wiadomości',
    'login.title':'Logowanie','login.identifier':'Identyfikator','login.password':'Hasło',
    'login.submit':'Zaloguj','login.reset':'Resetuj hasło z pliku','login.lang':'Język',
    'sb.messages':'Wiadomości','sb.groups':'Grupy','sb.create_group':'+ Utwórz grupę',
    'chat.placeholder':'Napisz wiadomość...','chat.send':'Wyślij','chat.select':'Wybierz kontakt lub grupę',
    'chat.settings':'Ustawienia czatu','chat.delete_history':'Usuń historię (tylko twoją)',
    'chat.block':'Zablokuj','chat.mute':'Wycisz','chat.mute_calls':'Wycisz połączenia',
    'chat.rename':'Zmień nazwę','chat.search':'Szukaj w rozmowie','chat.create_group':'Utwórz grupę',
    'chat.incoming':'Dzwoni do ciebie:',
    'admin.title':'Panel administratora','admin.manage_users':'Zarządzaj użytkownikami','admin.manage_perms':'Uprawnienia',
    'admin.reports':'Zgłoszenia','admin.create_user':'Utwórz konto','admin.sys_msg':'Wyślij wiadomość systemową',
    'admin.ringtones':'Dzwonki','admin.devices':'Urządzenia',
    'ringtones.title':'Dzwonki','ringtones.upload':'Wgraj (MP3/WAV, max 30s)',
    'ringtones.set_default':'Ustaw domyślny','ringtones.test':'Testuj','ringtones.delete':'Usuń',
    'ringtones.default':'(domyślny)','ringtones.builtin':'Wbudowany sygnał'
  },
  no: {
    'nav.logout':'Logg ut','nav.account':'Kontoinnstillinger','nav.admin':'Administrator',
    'nav.messages':'Til meldinger',
    'login.title':'Innlogging','login.identifier':'Identifikator','login.password':'Passord',
    'login.submit':'Logg inn','login.reset':'Tilbakestill passord med fil','login.lang':'Språk',
    'sb.messages':'Meldinger','sb.groups':'Grupper','sb.create_group':'+ Lag gruppe',
    'chat.placeholder':'Skriv en melding...','chat.send':'Send','chat.select':'Velg en kontakt eller gruppe',
    'chat.settings':'Chatinnstillinger','chat.delete_history':'Slett historikk (kun din)',
    'chat.block':'Blokker','chat.mute':'Demp','chat.mute_calls':'Demp anrop',
    'chat.rename':'Endre navn','chat.search':'Søk i samtale','chat.create_group':'Lag gruppe',
    'chat.incoming':'Innkommende anrop:',
    'admin.title':'Administrator','admin.manage_users':'Brukere','admin.manage_perms':'Rettigheter',
    'admin.reports':'Rapporter','admin.create_user':'Opprett konto','admin.sys_msg':'Send systemmelding',
    'admin.ringtones':'Ringetoner','admin.devices':'Enheter',
    'ringtones.title':'Ringetoner','ringtones.upload':'Last opp (MP3/WAV, maks 30s)',
    'ringtones.set_default':'Sett standard','ringtones.test':'Test','ringtones.delete':'Slett',
    'ringtones.default':'(standard)','ringtones.builtin':'Innebygd lyd'
  },
  de: {
    'nav.logout':'Abmelden','nav.account':'Kontoeinstellungen','nav.admin':'Adminbereich',
    'nav.messages':'Zu Nachrichten',
    'login.title':'Anmeldung','login.identifier':'Kennung','login.password':'Passwort',
    'login.submit':'Anmelden','login.reset':'Passwort per Datei zurücksetzen','login.lang':'Sprache',
    'sb.messages':'Nachrichten','sb.groups':'Gruppen','sb.create_group':'+ Gruppe erstellen',
    'chat.placeholder':'Nachricht eingeben...','chat.send':'Senden','chat.select':'Kontakt oder Gruppe auswählen',
    'chat.settings':'Chat-Einstellungen','chat.delete_history':'Verlauf löschen (nur eigener)',
    'chat.block':'Blockieren','chat.mute':'Stumm','chat.mute_calls':'Anrufe stumm',
    'chat.rename':'Umbenennen','chat.search':'Im Chat suchen','chat.create_group':'Gruppe erstellen',
    'chat.incoming':'Eingehender Anruf:',
    'admin.title':'Admin-Dashboard','admin.manage_users':'Benutzer','admin.manage_perms':'Berechtigungen',
    'admin.reports':'Meldungen','admin.create_user':'Konto erstellen','admin.sys_msg':'Systemnachricht senden',
    'admin.ringtones':'Klingeltöne','admin.devices':'Geräte',
    'ringtones.title':'Klingeltöne','ringtones.upload':'Hochladen (MP3/WAV, max 30s)',
    'ringtones.set_default':'Als Standard','ringtones.test':'Testen','ringtones.delete':'Löschen',
    'ringtones.default':'(Standard)','ringtones.builtin':'Eingebauter Ton'
  }
};

function getCookie(n){ const m=document.cookie.match(new RegExp('(?:^|; )'+n+'=([^;]*)')); return m?decodeURIComponent(m[1]):null; }
function setCookie(n,v){ document.cookie=n+'='+encodeURIComponent(v)+';path=/;max-age='+60*60*24*365; }
function getLang(){ const l=getCookie('lang'); return DICT[l]?l:'en'; }
function t(key){ const l=getLang(); return (DICT[l]&&DICT[l][key])||(DICT.en[key])||key; }

function applyI18n(root){
  (root||document).querySelectorAll('[data-i18n]').forEach(el=>{
    const k=el.getAttribute('data-i18n'); el.textContent=t(k);
  });
  (root||document).querySelectorAll('[data-i18n-placeholder]').forEach(el=>{
    const k=el.getAttribute('data-i18n-placeholder'); el.setAttribute('placeholder',t(k));
  });
  (root||document).querySelectorAll('[data-i18n-title]').forEach(el=>{
    const k=el.getAttribute('data-i18n-title'); el.setAttribute('title',t(k));
  });
}

function injectSwitcher(){
  if(document.getElementById('lang-switcher')) return;
  const sel=document.createElement('select');
  sel.id='lang-switcher';
  ['en','pl','no','de'].forEach(l=>{
    const o=document.createElement('option'); o.value=l; o.textContent=l.toUpperCase();
    if(l===getLang()) o.selected=true; sel.appendChild(o);
  });
  sel.addEventListener('change',()=>{ setCookie('lang',sel.value); location.reload(); });
  // Prefer placing inside the topbar to avoid overlapping other controls (Account Settings, etc.).
  const topbar = document.querySelector('.topbar');
  if (topbar) {
    sel.style.cssText='background:#111;color:#ddd;border:1px solid #444;padding:4px 6px;font-family:inherit;font-size:12px;margin-left:auto;order:-1;';
    topbar.insertBefore(sel, topbar.firstChild);
  } else {
    sel.style.cssText='position:fixed;bottom:10px;right:10px;z-index:9999;background:#111;color:#ddd;border:1px solid #444;padding:4px 6px;font-family:inherit;font-size:12px;';
    document.body.appendChild(sel);
  }
}

window.i18n = { t:t, apply:applyI18n, getLang:getLang };
document.addEventListener('DOMContentLoaded', function(){ applyI18n(); injectSwitcher(); });
})();
