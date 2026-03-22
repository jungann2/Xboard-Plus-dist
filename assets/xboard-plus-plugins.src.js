/**
 * Xboard-Plus Plugins
 */
(function() {
  'use strict';

  var SECURE_PATH = (window.settings && window.settings.secure_path) ? window.settings.secure_path : '';
  var API_BASE = '/api/v2/' + SECURE_PATH;
  var API_PUBLIC = '/api/v2';

  function getAuthToken() {
    try {
      var raw = localStorage.getItem('XBOARD_ACCESS_TOKEN');
      if (raw) {
        var parsed = JSON.parse(raw);
        var token = parsed && parsed.value;
        if (token && typeof token === 'string' && token.length > 10) {
          return token.indexOf('Bearer ') === 0 ? token : 'Bearer ' + token;
        }
      }
    } catch(e) {}
    return '';
  }

  function apiPost(endpoint, data, usePublic) {
    var token = getAuthToken();
    var base = usePublic ? API_PUBLIC : API_BASE;
    var headers = { 'Content-Type': 'application/json', 'Accept': 'application/json' };
    if (token) headers['Authorization'] = token;
    return fetch(base + endpoint, {
      method: 'POST', headers: headers, body: JSON.stringify(data)
    }).then(function(r) {
      var ct = r.headers.get('content-type') || '';
      if (ct.indexOf('text/html') >= 0) throw new Error('Route not found');
      return r.json().then(function(j) { if (!r.ok) throw new Error(j.message || 'Error'); return j; });
    });
  }

  function apiGet(endpoint, usePublic) {
    var token = getAuthToken();
    var base = usePublic ? API_PUBLIC : API_BASE;
    var headers = { 'Accept': 'application/json' };
    if (token) headers['Authorization'] = token;
    return fetch(base + endpoint, { headers: headers }).then(function(r) {
      var ct = r.headers.get('content-type') || '';
      if (ct.indexOf('text/html') >= 0) throw new Error('Route not found');
      return r.json().then(function(j) { if (!r.ok) throw new Error(j.message || 'Error'); return j; });
    });
  }

  function setReactInputValue(input, value) {
    var setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
    setter.call(input, String(value));
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
  }

  // ============================================================
  // ShareLinkParser
  // ============================================================
  var ShareLinkParser = {
    injected: false,
    createUI: function() {
      var c = document.createElement('div');
      c.id = 'xbp-share-link-parser';
      c.style.cssText = 'margin-bottom:16px;';
      c.innerHTML = '<div style="padding:12px 16px;border-radius:8px;border:1.5px dashed #93c5fd;background:rgba(59,130,246,0.04);">'
        + '<div style="font-size:12px;font-weight:600;color:#2563eb;margin-bottom:8px;font-family:ui-monospace,monospace;">'
        + '\ud83d\udccb \u7c98\u8d34 VasmaX \u5206\u4eab\u94fe\u63a5\u5feb\u901f\u586b\u5165</div>'
        + '<div style="display:flex;flex-direction:column;gap:8px;">'
        + '<input id="xbp-psl-input" type="text" placeholder="vless:// vmess:// trojan:// hysteria2:// tuic:// anytls://" style="width:100%;box-sizing:border-box;padding:6px 10px;font-size:12px;font-family:ui-monospace,monospace;border-radius:6px;border:1px solid #e2e8f0;background:#fff;outline:none;color:#1e293b;" />'
        + '<button id="xbp-psl-btn" type="button" style="width:100%;padding:6px 14px;font-size:12px;font-family:ui-monospace,monospace;border-radius:6px;border:none;background:#2563eb;color:#fff;cursor:pointer;">\u89e3\u6790\u586b\u5165</button>'
        + '</div>'
        + '<div id="xbp-psl-msg" style="font-size:11px;font-family:ui-monospace,monospace;margin-top:6px;display:none;"></div>'
        + '</div>';
      return c;
    },
    splitURI: function(uri) {
      var fragment = '', hashIdx = uri.indexOf('#');
      if (hashIdx !== -1) { fragment = decodeURIComponent(uri.substring(hashIdx + 1)); uri = uri.substring(0, hashIdx); }
      var query = '', qIdx = uri.indexOf('?');
      if (qIdx !== -1) { query = uri.substring(qIdx + 1); uri = uri.substring(0, qIdx); }
      var userInfo = '', atIdx = uri.indexOf('@');
      if (atIdx !== -1) { userInfo = uri.substring(0, atIdx); uri = uri.substring(atIdx + 1); }
      var lastColon = uri.lastIndexOf(':'), host, port;
      if (lastColon !== -1) { host = uri.substring(0, lastColon).replace(/^\[|\]$/g, ''); port = parseInt(uri.substring(lastColon + 1)) || 443; }
      else { host = uri.replace(/^\[|\]$/g, ''); port = 443; }
      var params = {};
      if (query) { query.split('&').forEach(function(pair) { var parts = pair.split('='); params[decodeURIComponent(parts[0])] = decodeURIComponent(parts.slice(1).join('=')); }); }
      return { userInfo: userInfo, host: host, port: port, params: params, fragment: fragment };
    },
    parseLocally: function(link) {
      link = link.trim();
      if (link.indexOf('vless://') === 0) return this.parseVless(link);
      if (link.indexOf('vmess://') === 0) return this.parseVmess(link);
      if (link.indexOf('trojan://') === 0) return this.parseTrojan(link);
      if (link.indexOf('hysteria2://') === 0 || link.indexOf('hy2://') === 0) return this.parseHysteria2(link);
      if (link.indexOf('tuic://') === 0) return this.parseTuic(link);
      if (link.indexOf('anytls://') === 0) return this.parseAnytls(link);
      throw new Error('\u4e0d\u652f\u6301\u7684\u534f\u8bae\u7c7b\u578b');
    },
    parseVless: function(link) {
      var p = this.splitURI(link.substring(8));
      var type = p.params.type || 'tcp', security = p.params.security || 'tls', sni = p.params.sni || '', fp = p.params.fp || '';
      var result = { type: 'vless', host: p.host, port: p.port, server_port: p.port, protocol_settings: { network: type, flow: p.params.flow || '' } };
      if (security === 'reality') { result.protocol_settings.tls = 2; result.protocol_settings.reality_settings = { server_name: sni, public_key: p.params.pbk || '', short_id: p.params.sid || '' }; if (fp) result.protocol_settings.utls = { enabled: true, fingerprint: fp }; }
      else if (security === 'tls') { result.protocol_settings.tls = 1; result.protocol_settings.tls_settings = { server_name: sni }; }
      else { result.protocol_settings.tls = 0; }
      var ns = {};
      if (type === 'ws') { ns.path = p.params.path || '/'; ns.headers = { Host: p.params.host || p.host }; }
      else if (type === 'grpc') { ns.serviceName = p.params.serviceName || ''; }
      else if (type === 'xhttp') { ns.path = p.params.path || '/'; }
      else if (type === 'httpupgrade') { ns.path = p.params.path || '/'; ns.host = p.params.host || p.host; }
      if (Object.keys(ns).length) result.protocol_settings.network_settings = ns;
      return result;
    },
    parseVmess: function(link) {
      var json = JSON.parse(atob(link.substring(8)));
      var host = json.add || '', port = parseInt(json.port) || 443, net = json.net || 'tcp', tls = json.tls === 'tls' ? 1 : 0;
      var result = { type: 'vmess', host: host, port: port, server_port: port, protocol_settings: { tls: tls, network: net } };
      if (tls && json.sni) result.protocol_settings.tls_settings = { server_name: json.sni };
      var ns = {};
      if (net === 'ws') { ns.path = json.path || '/'; ns.headers = { Host: json.host || host }; }
      else if (net === 'grpc') { ns.serviceName = json.path || ''; }
      else if (net === 'httpupgrade') { ns.path = json.path || '/'; ns.host = json.host || host; }
      if (Object.keys(ns).length) result.protocol_settings.network_settings = ns;
      return result;
    },
    parseTrojan: function(link) {
      var p = this.splitURI(link.substring(9));
      var type = p.params.type || 'tcp', sni = p.params.sni || '';
      var result = { type: 'trojan', host: p.host, port: p.port, server_port: p.port, protocol_settings: { network: type, server_name: sni } };
      var ns = {};
      if (type === 'grpc') { ns.serviceName = p.params.serviceName || ''; }
      else if (type === 'ws') { ns.path = p.params.path || '/'; ns.headers = { Host: p.params.host || p.host }; }
      if (Object.keys(ns).length) result.protocol_settings.network_settings = ns;
      return result;
    },
    parseHysteria2: function(link) {
      var prefix = link.indexOf('hy2://') === 0 ? 6 : 12;
      var p = this.splitURI(link.substring(prefix));
      var result = { type: 'hysteria', host: p.host, port: p.port, server_port: p.port, protocol_settings: { version: 2, tls: { server_name: p.params.sni || '', allow_insecure: p.params.insecure === '1' } } };
      if (p.params.obfs) result.protocol_settings.obfs = { open: true, type: p.params.obfs, password: p.params['obfs-password'] || '' };
      return result;
    },
    parseTuic: function(link) {
      var p = this.splitURI(link.substring(7));
      return { type: 'tuic', host: p.host, port: p.port, server_port: p.port, protocol_settings: { version: 5, tls: { server_name: p.params.sni || '', allow_insecure: p.params.insecure === '1' }, alpn: p.params.alpn || '' } };
    },
    parseAnytls: function(link) {
      var p = this.splitURI(link.substring(9));
      return { type: 'anytls', host: p.host, port: p.port, server_port: p.port, protocol_settings: { tls: { server_name: p.params.sni || '', allow_insecure: p.params.insecure === '1' } } };
    },
    parse: function() {
      var self = this;
      var input = document.getElementById('xbp-psl-input');
      var btn = document.getElementById('xbp-psl-btn');
      var msg = document.getElementById('xbp-psl-msg');
      var link = input ? input.value.trim() : '';
      if (!link) return;
      btn.disabled = true; btn.textContent = '\u89e3\u6790\u4e2d...'; btn.style.opacity = '0.6'; msg.style.display = 'none';
      try {
        var data = self.parseLocally(link);
        self.fillForm(data);
        msg.style.display = 'block'; msg.style.color = '#16a34a'; msg.textContent = '\u2713 \u89e3\u6790\u6210\u529f'; input.value = '';
      } catch (err) {
        msg.style.display = 'block'; msg.style.color = '#dc2626'; msg.textContent = '\u2717 ' + (err.message || '\u89e3\u6790\u5931\u8d25');
      } finally { btn.disabled = false; btn.textContent = '\u89e3\u6790\u586b\u5165'; btn.style.opacity = '1'; }
    },
    fillForm: function(data) {
      var self = this;
      if (data.type) self.setProtocolType(data.type);
      setTimeout(function() {
        if (data.host) self.setInputValue('host', data.host);
        if (data.port) self.setInputValue('port', data.port);
        if (data.server_port) self.setInputValue('server_port', data.server_port);
        setTimeout(function() { if (data.protocol_settings) self.fillProtocolSettings(data.protocol_settings); }, 300);
      }, 200);
    },
    setInputValue: function(fieldName, value) {
      var dialog = document.querySelector('[role="dialog"]');
      if (!dialog) return;
      var inputs = dialog.querySelectorAll('input');
      for (var i = 0; i < inputs.length; i++) {
        var formItem = inputs[i].closest('.space-y-2') || (inputs[i].parentElement ? inputs[i].parentElement.parentElement : null);
        if (!formItem) continue;
        var label = formItem.querySelector('label');
        var labelText = label ? label.textContent : '';
        var match = false;
        if (fieldName === 'host' && (labelText.indexOf('\u8282\u70b9\u5730\u5740') >= 0 || labelText.indexOf('\u5730\u5740') >= 0)) match = true;
        if (fieldName === 'port' && labelText.indexOf('\u8fde\u63a5\u7aef\u53e3') >= 0) match = true;
        if (fieldName === 'server_port' && labelText.indexOf('\u670d\u52a1\u7aef\u53e3') >= 0) match = true;
        if (match) { setReactInputValue(inputs[i], value); return; }
      }
    },
    setProtocolType: function(type) {
      var dialog = document.querySelector('[role="dialog"]');
      if (!dialog) return;
      var sel = dialog.querySelector('button[role="combobox"]');
      if (!sel) return;
      sel.click();
      setTimeout(function() {
        var opts = document.querySelectorAll('[role="option"]');
        for (var i = 0; i < opts.length; i++) {
          if ((opts[i].textContent || '').toLowerCase().indexOf(type.toLowerCase()) >= 0) { opts[i].click(); return; }
        }
        sel.click();
      }, 100);
    },
    fillProtocolSettings: function(settings) {
      var dialog = document.querySelector('[role="dialog"]');
      if (!dialog) return;
      var flat = {}; this.flattenSettings(settings, flat);
      var inputs = dialog.querySelectorAll('input');
      for (var i = 0; i < inputs.length; i++) {
        var formItem = inputs[i].closest('.space-y-2') || (inputs[i].parentElement ? inputs[i].parentElement.parentElement : null);
        if (!formItem) continue;
        var lt = ((formItem.querySelector('label') || {}).textContent || '').toLowerCase();
        for (var key in flat) {
          var v = flat[key]; if (v === undefined || v === null || v === '') continue;
          var k = key.toLowerCase(), m = false;
          if (k === 'server_name' && (lt.indexOf('sni') >= 0 || lt.indexOf('server_name') >= 0)) m = true;
          if (k === 'path' && lt.indexOf('path') >= 0) m = true;
          if (k === 'servicename' && lt.indexOf('service') >= 0) m = true;
          if (k === 'public_key' && (lt.indexOf('public') >= 0 || lt.indexOf('pbk') >= 0)) m = true;
          if (k === 'short_id' && (lt.indexOf('short') >= 0 || lt.indexOf('sid') >= 0)) m = true;
          if (k === 'fingerprint' && lt.indexOf('fingerprint') >= 0) m = true;
          if (m) { setReactInputValue(inputs[i], v); break; }
        }
      }
      this.setSelectFields(dialog, settings);
    },
    flattenSettings: function(obj, result) {
      for (var key in obj) { var v = obj[key]; if (v && typeof v === 'object' && !Array.isArray(v)) this.flattenSettings(v, result); else result[key] = v; }
    },
    setSelectFields: function(dialog, settings) {
      if (!settings.network) return;
      var cbs = dialog.querySelectorAll('button[role="combobox"]');
      for (var i = 1; i < cbs.length; i++) {
        var fi = cbs[i].closest('.space-y-2') || (cbs[i].parentElement ? cbs[i].parentElement.parentElement : null);
        var lt = ((fi ? fi.querySelector('label') : null) || {}).textContent || '';
        lt = lt.toLowerCase();
        if (lt.indexOf('\u4f20\u8f93') >= 0 || lt.indexOf('network') >= 0 || lt.indexOf('transport') >= 0) {
          cbs[i].click(); var net = settings.network;
          setTimeout(function() {
            var opts = document.querySelectorAll('[role="option"]'); var found = false;
            for (var j = 0; j < opts.length; j++) { if ((opts[j].textContent || '').toLowerCase().indexOf(net.toLowerCase()) >= 0) { opts[j].click(); found = true; break; } }
            if (!found) cbs[i].click();
          }, 100);
          break;
        }
      }
    },
    observe: function() {
      var self = this;
      new MutationObserver(function() {
        var dialog = document.querySelector('[role="dialog"]');
        if (!dialog) { self.injected = false; return; }
        var title = dialog.querySelector('h2, [class*="DialogTitle"]');
        if (!title) return;
        var tt = title.textContent || '';
        if (tt.indexOf('\u8282\u70b9') < 0 && tt.toLowerCase().indexOf('node') < 0) return;
        if (dialog.querySelector('#xbp-share-link-parser')) return;
        var area = dialog.querySelector('[class*="overflow-y-auto"]') || dialog.querySelector('form');
        if (!area || !area.firstElementChild) return;
        var ui = self.createUI();
        area.insertBefore(ui, area.firstElementChild);
        document.getElementById('xbp-psl-btn').addEventListener('click', function() { self.parse(); });
        document.getElementById('xbp-psl-input').addEventListener('keydown', function(e) { if (e.key === 'Enter') { e.preventDefault(); self.parse(); } });
        self.injected = true;
      }).observe(document.body, { childList: true, subtree: true });
    }
  };

  // ============================================================
  // CopyTokenButton
  // ============================================================
  var CopyTokenButton = {
    observe: function() {
      new MutationObserver(function() {
        if (document.getElementById('xbp-copy-token')) return;
        var labels = document.querySelectorAll('label');
        var tokenInput = null;
        for (var i = 0; i < labels.length; i++) {
          var text = labels[i].textContent || '';
          if (text.indexOf('\u901a\u8baf\u5bc6\u94a5') < 0 && text.indexOf('server_token') < 0) continue;
          var fi = labels[i].closest('.space-y-2') || labels[i].parentElement;
          if (fi) { tokenInput = fi.querySelector('input'); break; }
        }
        if (!tokenInput) return;
        var ip = tokenInput.parentElement;
        if (!ip) return;
        if (getComputedStyle(ip).position === 'static') ip.style.position = 'relative';
        var svg = ip.querySelector('svg');
        var gr = 8;
        if (svg && svg.parentElement) gr = parseInt(getComputedStyle(svg.parentElement).right) || 8;
        var btn = document.createElement('button');
        btn.id = 'xbp-copy-token'; btn.type = 'button'; btn.title = '\u590d\u5236\u5bc6\u94a5';
        btn.style.cssText = 'position:absolute;top:50%;transform:translateY(-50%);right:' + (gr + 28) + 'px;background:none;border:none;cursor:pointer;color:#94a3b8;padding:2px;display:flex;align-items:center;z-index:1;';
        btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
        btn.addEventListener('mouseenter', function() { btn.style.color = '#2563eb'; });
        btn.addEventListener('mouseleave', function() { btn.style.color = '#94a3b8'; });
        btn.addEventListener('click', function(e) {
          e.preventDefault(); e.stopPropagation();
          var val = tokenInput.value || '';
          if (!val) return;
          navigator.clipboard.writeText(val).then(function() {
            btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#16a34a" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>';
            btn.style.color = '#16a34a';
            setTimeout(function() {
              btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
              btn.style.color = '#94a3b8';
            }, 1500);
          });
        });
        ip.appendChild(btn);
      }).observe(document.body, { childList: true, subtree: true });
    }
  };

  // ============================================================
  // CaptchaConfig - Admin settings panel
  // ============================================================
  var CaptchaConfig = {
    injected: false,
    createUI: function() {
      var c = document.createElement('div');
      c.id = 'xbp-captcha-config';
      c.style.cssText = 'margin-bottom:24px;padding:16px;border-radius:8px;border:1px solid #e2e8f0;background:#f8fafc;';
      c.innerHTML = '<div style="font-size:14px;font-weight:600;color:#1e293b;margin-bottom:12px;">\ud83d\udd10 \u672c\u5730\u9a8c\u8bc1\u7801\u8bbe\u7f6e</div>'
        + '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">'
        + '<div><label style="font-size:12px;color:#64748b;display:block;margin-bottom:4px;">\u5b57\u7b26\u9a8c\u8bc1\u7801</label>'
        + '<select id="xbp-cc-char" style="width:100%;padding:6px 8px;border-radius:6px;border:1px solid #e2e8f0;font-size:12px;background:#fff;">'
        + '<option value="0">\u5173\u95ed</option><option value="1">\u524d\u53f0\u542f\u7528</option><option value="2">\u540e\u53f0\u542f\u7528</option><option value="3">\u524d\u53f0+\u540e\u53f0</option></select></div>'
        + '<div><label style="font-size:12px;color:#64748b;display:block;margin-bottom:4px;">\u7b97\u672f\u9a8c\u8bc1\u7801</label>'
        + '<select id="xbp-cc-math" style="width:100%;padding:6px 8px;border-radius:6px;border:1px solid #e2e8f0;font-size:12px;background:#fff;">'
        + '<option value="0">\u5173\u95ed</option><option value="1">\u524d\u53f0\u542f\u7528</option><option value="2">\u540e\u53f0\u542f\u7528</option><option value="3">\u524d\u53f0+\u540e\u53f0</option></select></div>'
        + '<div><label style="font-size:12px;color:#64748b;display:block;margin-bottom:4px;">\u5b57\u7b26\u96c6</label>'
        + '<select id="xbp-cc-charset" style="width:100%;padding:6px 8px;border-radius:6px;border:1px solid #e2e8f0;font-size:12px;background:#fff;">'
        + '<option value="mixed">\u6df7\u5408</option><option value="number">\u7eaf\u6570\u5b57</option><option value="upper">\u5927\u5199\u5b57\u6bcd</option><option value="lower">\u5c0f\u5199\u5b57\u6bcd</option></select></div>'
        + '<div><label style="font-size:12px;color:#64748b;display:block;margin-bottom:4px;">\u5b57\u7b26\u957f\u5ea6</label>'
        + '<select id="xbp-cc-length" style="width:100%;padding:6px 8px;border-radius:6px;border:1px solid #e2e8f0;font-size:12px;background:#fff;">'
        + '<option value="4">4</option><option value="5">5</option><option value="6">6</option></select></div>'
        + '<div style="grid-column:span 2;"><label style="font-size:12px;color:#64748b;display:block;margin-bottom:4px;">\u5bc6\u4fdd\u5361\uff08\u4ec5\u540e\u53f0\u767b\u5f55\uff09</label>'
        + '<select id="xbp-cc-seccard" style="width:100%;padding:6px 8px;border-radius:6px;border:1px solid #e2e8f0;font-size:12px;background:#fff;">'
        + '<option value="0">\u5173\u95ed</option><option value="1">\u542f\u7528</option></select></div>'
        + '</div>'
        + '<div style="margin-top:12px;display:flex;gap:8px;">'
        + '<button id="xbp-cc-save" type="button" style="padding:6px 16px;font-size:12px;border-radius:6px;border:none;background:#2563eb;color:#fff;cursor:pointer;">\u4fdd\u5b58</button>'
        + '<span id="xbp-cc-msg" style="font-size:11px;color:#64748b;line-height:30px;"></span></div>';
      return c;
    },
    loadConfig: function() {
      apiGet('/config/fetch', false).then(function(res) {
        var d = (res && res.data) || {};
        var el;
        el = document.getElementById('xbp-cc-char'); if (el) el.value = String(d.local_captcha_char_enable || 0);
        el = document.getElementById('xbp-cc-math'); if (el) el.value = String(d.local_captcha_math_enable || 0);
        el = document.getElementById('xbp-cc-charset'); if (el) el.value = d.local_captcha_charset || 'mixed';
        el = document.getElementById('xbp-cc-length'); if (el) el.value = String(d.local_captcha_length || 4);
        el = document.getElementById('xbp-cc-seccard'); if (el) el.value = String(d.security_card_enable || 0);
      }).catch(function() {});
    },
    saveConfig: function() {
      var data = {
        local_captcha_char_enable: parseInt(document.getElementById('xbp-cc-char').value),
        local_captcha_math_enable: parseInt(document.getElementById('xbp-cc-math').value),
        local_captcha_charset: document.getElementById('xbp-cc-charset').value,
        local_captcha_length: parseInt(document.getElementById('xbp-cc-length').value),
        security_card_enable: parseInt(document.getElementById('xbp-cc-seccard').value)
      };
      var msg = document.getElementById('xbp-cc-msg');
      apiPost('/config/save', data, false).then(function() {
        if (msg) { msg.style.color = '#16a34a'; msg.textContent = '\u2713 \u5df2\u4fdd\u5b58'; setTimeout(function() { msg.textContent = ''; }, 800); }
      }).catch(function(err) {
        if (msg) { msg.style.color = '#dc2626'; msg.textContent = '\u2717 ' + (err.message || '\u4fdd\u5b58\u5931\u8d25'); }
      });
    },
    observe: function() {
      var self = this;
      new MutationObserver(function() {
        if (document.getElementById('xbp-captcha-config')) return;
        var els = document.querySelectorAll('label, span, div');
        var anchor = null;
        for (var i = 0; i < els.length; i++) {
          var t = els[i].textContent || '';
          if (t.indexOf('\u542f\u7528\u7b2c\u4e09\u65b9\u9a8c\u8bc1\u7801') >= 0 || t.indexOf('captcha_enable') >= 0) {
            anchor = els[i].closest('.space-y-2') || els[i].closest('[class*="card"]') || els[i].parentElement;
            break;
          }
        }
        if (!anchor) return;
        var ui = self.createUI();
        anchor.parentElement.insertBefore(ui, anchor);
        self.loadConfig();
        document.getElementById('xbp-cc-save').addEventListener('click', function() { self.saveConfig(); });
        self.injected = true;
      }).observe(document.body, { childList: true, subtree: true });
    }
  };

  // ============================================================
  // LoginCaptcha
  // ============================================================
  var LoginCaptcha = {
    captchaData: {},
    securityCardData: null,
    containerEl: null,
    scene: '',

    getScene: function() {
      return SECURE_PATH ? 'admin' : 'frontend';
    },

    findLoginContainer: function() {
      var pw = document.querySelector('input[type="password"]');
      if (!pw) return null;
      // Walk up from password input, stop at the smallest container that also has a login button
      var el = pw.parentElement;
      for (var i = 0; i < 10 && el; i++) {
        var btns = el.querySelectorAll('button');
        var hasLoginBtn = false;
        for (var j = 0; j < btns.length; j++) {
          var txt = btns[j].textContent || '';
          if (txt.indexOf('\u767b\u5f55') >= 0 || txt.indexOf('\u767b\u5165') >= 0 || txt.toLowerCase().indexOf('login') >= 0 || txt.toLowerCase().indexOf('sign in') >= 0 || btns[j].type === 'submit') {
            hasLoginBtn = true; break;
          }
        }
        if (hasLoginBtn) {
          console.log('[Xboard-Plus] found container at depth', i, el.tagName, el.className);
          return el;
        }
        el = el.parentElement;
      }
      return null;
    },

    _configCache: null,
    _configPromise: null,

    preloadConfig: function() {
      var self = this;
      self.scene = self.getScene();
      // Single request: get config + all captcha images + security card in one call
      self._allReadyPromise = apiGet('/captcha/bundle?scene=' + self.scene, true).then(function(res) {
        var d = (res && res.data) || {};
        self._configCache = d.types || [];
        if (d.char) self.captchaData.char = d.char;
        if (d.math) self.captchaData.math = d.math;
        if (d.security_card && d.security_card.positions) self.securityCardData = d.security_card;
      }).catch(function(err) { console.warn('[Xboard-Plus] bundle error:', err); });
    },

    loadCaptchas: function() {
      var self = this;
      // If preload already done, just return resolved promise
      if (self._allReadyPromise) {
        return self._allReadyPromise;
      }
      // Fallback: single bundle request
      self.scene = self.getScene();
      self.captchaData = {};
      self.securityCardData = null;
      return apiGet('/captcha/bundle?scene=' + self.scene, true).then(function(res) {
        var d = (res && res.data) || {};
        if (d.char) self.captchaData.char = d.char;
        if (d.math) self.captchaData.math = d.math;
        if (d.security_card && d.security_card.positions) self.securityCardData = d.security_card;
      }).catch(function(err) { console.warn('[Xboard-Plus] loadCaptchas error:', err); });
    },

    renderCaptchaUI: function() {
      var self = this;
      if (self.containerEl && self.containerEl.parentElement) {
        self.containerEl.parentElement.removeChild(self.containerEl);
      }
      var c = document.createElement('div');
      c.id = 'xbp-login-captcha';
      c.style.cssText = 'margin:12px 0;';
      var html = '';

      if (self.captchaData.char) {
        html += '<div style="margin-bottom:8px;"><div style="display:flex;align-items:center;gap:6px;">'
          + '<img id="xbp-lc-char-img" src="' + self.captchaData.char.image + '" style="height:34px;border-radius:4px;cursor:pointer;" />'
          + '<input id="xbp-lc-char-input" type="text" placeholder="\u9a8c\u8bc1\u7801\uff08\u533a\u5206\u5927\u5c0f\u5199\uff09" autocomplete="off" '
          + 'style="flex:1;padding:6px 8px;border-radius:6px;border:1px solid #e2e8f0;font-size:12px;outline:none;box-sizing:border-box;" />'
          + '</div></div>';
      }
      if (self.captchaData.math) {
        html += '<div style="margin-bottom:8px;"><div style="display:flex;align-items:center;gap:6px;">'
          + '<img id="xbp-lc-math-img" src="' + self.captchaData.math.image + '" style="height:34px;border-radius:4px;cursor:pointer;" />'
          + '<input id="xbp-lc-math-input" type="text" placeholder="\u8bf7\u8f93\u5165\u8ba1\u7b97\u7ed3\u679c" autocomplete="off" '
          + 'style="flex:1;padding:6px 8px;border-radius:6px;border:1px solid #e2e8f0;font-size:12px;outline:none;box-sizing:border-box;" />'
          + '</div></div>';
      }
      if (self.securityCardData) {
        var pos = self.securityCardData.positions;
        html += '<div style="margin-bottom:8px;padding:8px 10px;border-radius:6px;border:1px solid #fbbf24;background:#fffbeb;">'
          + '<div style="font-size:11px;font-weight:600;color:#92400e;margin-bottom:6px;">\ud83d\udcca \u5bc6\u4fdd\u5361\u9a8c\u8bc1</div>'
          + '<div style="display:flex;gap:10px;justify-content:center;">';
        for (var i = 0; i < pos.length; i++) {
          html += '<div style="display:flex;flex-direction:column;align-items:center;gap:4px;">'
            + '<span style="font-size:12px;font-weight:700;color:#92400e;">' + pos[i] + '</span>'
            + '<input class="xbp-lc-sc-input" type="text" data-pos="' + pos[i] + '" placeholder="" autocomplete="off" '
            + 'style="width:56px;padding:4px 6px;border-radius:5px;border:1px solid #fbbf24;font-size:12px;outline:none;box-sizing:border-box;text-align:center;" />'
            + '</div>';
        }
        html += '</div></div>';
      }

      if (!html) return null;
      c.innerHTML = html;
      self.containerEl = c;
      return c;
    },

    injectIntoLogin: function() {
      var self = this;
      var lc = self.findLoginContainer();
      if (!lc) { console.warn('[Xboard-Plus] login container not found'); return; }
      var ui = self.renderCaptchaUI();
      if (!ui) { console.warn('[Xboard-Plus] no captcha UI to render'); return; }

      // Find submit button - search broadly
      var sb = null;
      var allBtns = lc.querySelectorAll('button');
      for (var i = 0; i < allBtns.length; i++) {
        var txt = allBtns[i].textContent || '';
        var txtL = txt.toLowerCase();
        if (allBtns[i].type === 'submit' || txt.indexOf('\u767b\u5f55') >= 0 || txt.indexOf('\u767b\u5165') >= 0 || txtL.indexOf('login') >= 0 || txtL.indexOf('sign in') >= 0) { sb = allBtns[i]; break; }
      }

      if (sb) {
        // For Naive UI: button might be wrapped in extra divs, insert before the outermost wrapper that's still inside lc
        var insertTarget = sb;
        while (insertTarget.parentElement && insertTarget.parentElement !== lc) {
          insertTarget = insertTarget.parentElement;
        }
        if (insertTarget.parentElement === lc) {
          lc.insertBefore(ui, insertTarget);
        } else {
          sb.parentElement.insertBefore(ui, sb);
        }
      } else {
        // Fallback: insert before last child or append
        var pw = lc.querySelector('input[type="password"]');
        if (pw) {
          var pwBlock = pw;
          while (pwBlock.parentElement && pwBlock.parentElement !== lc) pwBlock = pwBlock.parentElement;
          if (pwBlock.nextSibling) {
            lc.insertBefore(ui, pwBlock.nextSibling);
          } else {
            lc.appendChild(ui);
          }
        } else {
          lc.appendChild(ui);
        }
      }
      console.log('[Xboard-Plus] captcha injected into login');

      // Bind refresh clicks
      var ci = document.getElementById('xbp-lc-char-img');
      if (ci) ci.addEventListener('click', function() {
        apiGet('/captcha/generate?type=char', true).then(function(r) { self.captchaData.char = r.data; ci.src = r.data.image; });
      });
      var mi = document.getElementById('xbp-lc-math-img');
      if (mi) mi.addEventListener('click', function() {
        apiGet('/captcha/generate?type=math', true).then(function(r) { self.captchaData.math = r.data; mi.src = r.data.image; });
      });
    },

    getCaptchaPayload: function() {
      var self = this;
      var p = { scene: self.scene };
      if (self.captchaData.char) {
        p.char_captcha_id = self.captchaData.char.captcha_id;
        var el = document.getElementById('xbp-lc-char-input');
        p.char_captcha_input = el ? el.value.trim() : '';
      }
      if (self.captchaData.math) {
        p.math_captcha_id = self.captchaData.math.captcha_id;
        var el2 = document.getElementById('xbp-lc-math-input');
        p.math_captcha_input = el2 ? el2.value.trim() : '';
      }
      if (self.securityCardData) {
        p.security_card_challenge_id = self.securityCardData.challenge_id;
        var inputs = document.querySelectorAll('.xbp-lc-sc-input');
        var answers = [];
        for (var i = 0; i < inputs.length; i++) answers.push(inputs[i].value.trim());
        p.security_card_answers = answers;
      }
      return p;
    },

    refreshCaptchas: function() {
      var self = this;
      var promises = [];
      if (self.captchaData.char) {
        promises.push(apiGet('/captcha/generate?type=char', true).then(function(r) {
          self.captchaData.char = r.data;
          var img = document.getElementById('xbp-lc-char-img'); if (img) img.src = r.data.image;
          var inp = document.getElementById('xbp-lc-char-input'); if (inp) inp.value = '';
        }));
      }
      if (self.captchaData.math) {
        promises.push(apiGet('/captcha/generate?type=math', true).then(function(r) {
          self.captchaData.math = r.data;
          var img = document.getElementById('xbp-lc-math-img'); if (img) img.src = r.data.image;
          var inp = document.getElementById('xbp-lc-math-input'); if (inp) inp.value = '';
        }));
      }
      if (self.securityCardData) {
        promises.push(apiGet('/security-card/challenge', true).then(function(r) {
          if (r.data && r.data.positions) { self.securityCardData = r.data; self.injectIntoLogin(); }
        }));
      }
      return Promise.all(promises);
    },

    hookFormSubmit: function() {
      var self = this;

      // Hook XHR
      var origOpen = XMLHttpRequest.prototype.open;
      var origSend = XMLHttpRequest.prototype.send;
      XMLHttpRequest.prototype.open = function(method, url) {
        this._xbpMethod = method; this._xbpUrl = url;
        return origOpen.apply(this, arguments);
      };
      XMLHttpRequest.prototype.send = function(body) {
        var xhr = this;
        if (this._xbpMethod && this._xbpMethod.toUpperCase() === 'POST' && this._xbpUrl && self.shouldInject(this._xbpUrl)) {
          try {
            var d = JSON.parse(body);
            var cp = self.getCaptchaPayload();
            for (var k in cp) d[k] = cp[k];
            body = JSON.stringify(d);
          } catch(e) {}
          xhr.addEventListener('load', function() {
            if (xhr.status >= 400) setTimeout(function() { self.refreshCaptchas(); }, 500);
          });
        }
        return origSend.call(this, body);
      };

      // Hook fetch
      var origFetch = window.fetch;
      window.fetch = function(input, init) {
        var url = typeof input === 'string' ? input : (input && input.url ? input.url : '');
        if (init && init.method && init.method.toUpperCase() === 'POST' && self.shouldInject(url) && init.body) {
          try {
            var d = JSON.parse(init.body);
            var cp = self.getCaptchaPayload();
            for (var k in cp) d[k] = cp[k];
            init.body = JSON.stringify(d);
          } catch(e) {}
          return origFetch.call(this, input, init).then(function(resp) {
            if (!resp.ok) setTimeout(function() { self.refreshCaptchas(); }, 500);
            return resp;
          });
        }
        return origFetch.call(this, input, init);
      };
    },

    shouldInject: function(url) {
      if (!url) return false;
      var p = ['/auth/login', '/auth/register', '/comm/sendEmailVerify'];
      for (var i = 0; i < p.length; i++) { if (url.indexOf(p[i]) >= 0) return true; }
      return false;
    },

    observe: function() {
      var self = this;
      var lastCheck = 0;

      // Also use interval as fallback for SPAs where MutationObserver may miss
      var checkLogin = function() {
        if (document.getElementById('xbp-login-captcha')) return;
        var pw = document.querySelector('input[type="password"]');
        if (!pw) return;
        console.log('[Xboard-Plus] password input found, loading captchas...');
        self.loadCaptchas().then(function() {
          if (!document.getElementById('xbp-login-captcha')) {
            self.injectIntoLogin();
          }
        });
      };

      new MutationObserver(function() {
        var now = Date.now();
        if (now - lastCheck < 200) return;
        lastCheck = now;
        checkLogin();
      }).observe(document.body, { childList: true, subtree: true });

      // Fallback: poll every 2s for 30s in case MutationObserver misses it
      var pollCount = 0;
      var pollTimer = setInterval(function() {
        pollCount++;
        if (pollCount > 15 || document.getElementById('xbp-login-captcha')) {
          clearInterval(pollTimer);
          return;
        }
        checkLogin();
      }, 800);
    }
  };

  // ============================================================
  // Init
  // ============================================================
  // Inject style to widen login card (admin only)
  if (SECURE_PATH) {
    var styleEl = document.createElement('style');
    styleEl.textContent = '.n-card, [class*="card"], [class*="Card"], .n-card-bordered { min-width: 360px !important; max-width: 400px !important; } #xbp-login-captcha { max-width: 100%; }';
    document.head.appendChild(styleEl);
  }

  function init() {
    ShareLinkParser.observe();
    CopyTokenButton.observe();
    CaptchaConfig.observe();
    LoginCaptcha.hookFormSubmit();
    // Preload captcha config immediately so data is ready when password field appears
    LoginCaptcha.preloadConfig();
    LoginCaptcha.observe();
    console.log('[Xboard-Plus] Plugins loaded, scene:', LoginCaptcha.getScene());
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
