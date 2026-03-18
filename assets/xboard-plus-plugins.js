/**
 * Xboard-Plus 插件系统
 * 
 * 所有 Xboard-Plus 自定义功能的入口文件。
 * 通过 DOM 观察器和事件钩子与主 JS 交互，不修改主 JS 代码。
 * 
 * 架构：
 * - 主 JS (index-CZ2c_Z8h.js) 保持原样，不做业务修改
 * - 本文件监听 DOM 变化，在合适时机注入自定义 UI
 * - 通过 window.settings.secure_path 获取 API 路径
 * - 通过 fetch 直接调用后端 API
 */

(function() {
  'use strict';

  const SECURE_PATH = window?.settings?.secure_path ?? '';
  const API_BASE = '/api/v2/' + SECURE_PATH;

  // ============================================================
  // 工具函数
  // ============================================================

  /**
   * 从 localStorage 获取 auth token
   * Xboard 使用 Sanctum，登录后返回 auth_data = "Bearer xxx"
   * 前端通常用 zustand persist 存到 localStorage
   */
  function getAuthToken() {
    try {
      const keys = Object.keys(localStorage);
      for (const key of keys) {
        const val = localStorage.getItem(key);
        if (!val || val.length < 20) continue;

        // 直接包含 Bearer 的值
        if (val.startsWith('Bearer ') || val.startsWith('"Bearer ')) {
          return val.replace(/^"|"$/g, '');
        }

        // 尝试解析 JSON（zustand persist 格式）
        try {
          const parsed = JSON.parse(val);
          // 检查常见的 zustand state 结构
          const authData = parsed?.state?.auth_data
            || parsed?.state?.authData
            || parsed?.state?.token
            || parsed?.auth_data
            || parsed?.authData
            || parsed?.token;
          if (authData && typeof authData === 'string' && authData.length > 20) {
            return authData.startsWith('Bearer ') ? authData : 'Bearer ' + authData;
          }
        } catch(e) { /* not JSON */ }
      }
    } catch(e) {}
    return '';
  }

  /** POST JSON 请求，自动带 auth token */
  async function apiPost(endpoint, data) {
    const token = getAuthToken();
    const url = API_BASE + endpoint;
    console.log('[Xboard-Plus] API POST:', url, 'token:', token ? '有' : '无');

    const resp = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        ...(token ? { 'Authorization': token } : {})
      },
      body: JSON.stringify(data)
    });

    // 检查是否返回了 HTML（说明路由未匹配）
    const contentType = resp.headers.get('content-type') || '';
    if (contentType.includes('text/html')) {
      throw new Error('路由未找到 (返回了HTML)。请在 WSL 中重启 Octane: docker compose restart web');
    }

    const json = await resp.json();
    if (!resp.ok) throw new Error(json.message || '请求失败 (' + resp.status + ')');
    return json;
  }

  // ============================================================
  // 插件：分享链接解析器（添加节点弹窗）
  // ============================================================

  const ShareLinkParser = {
    injected: false,

    /** 创建解析器 UI 元素 */
    createUI() {
      const container = document.createElement('div');
      container.id = 'xbp-share-link-parser';
      container.style.cssText = 'margin-bottom:16px;';
      container.innerHTML = `
        <div style="padding:12px 16px;border-radius:8px;border:1.5px dashed #93c5fd;background:rgba(59,130,246,0.04);">
          <div style="font-size:12px;font-weight:600;color:#2563eb;margin-bottom:8px;font-family:ui-monospace,monospace;">
            📋 粘贴 VasmaX 分享链接快速填入
          </div>
          <div style="display:flex;flex-direction:column;gap:8px;">
            <input id="xbp-psl-input" type="text"
              placeholder="vless:// vmess:// trojan:// hysteria2:// tuic:// anytls://"
              style="width:100%;box-sizing:border-box;padding:6px 10px;font-size:12px;font-family:ui-monospace,monospace;
                     border-radius:6px;border:1px solid #e2e8f0;background:#fff;outline:none;
                     color:#1e293b;" />
            <button id="xbp-psl-btn" type="button"
              style="width:100%;padding:6px 14px;font-size:12px;font-family:ui-monospace,monospace;
                     border-radius:6px;border:none;background:#2563eb;color:#fff;cursor:pointer;
                     white-space:nowrap;">
              解析填入
            </button>
          </div>
          <div id="xbp-psl-msg" style="font-size:11px;font-family:ui-monospace,monospace;margin-top:6px;display:none;"></div>
        </div>
      `;
      return container;
    },

    /** 在前端直接解析链接（不依赖后端 API） */
    parseLocally(link) {
      link = link.trim();

      if (link.startsWith('vless://')) return this.parseVless(link);
      if (link.startsWith('vmess://')) return this.parseVmess(link);
      if (link.startsWith('trojan://')) return this.parseTrojan(link);
      if (link.startsWith('hysteria2://') || link.startsWith('hy2://')) return this.parseHysteria2(link);
      if (link.startsWith('tuic://')) return this.parseTuic(link);
      if (link.startsWith('anytls://')) return this.parseAnytls(link);

      throw new Error('不支持的协议类型');
    },

    /** 解析 URI 通用部分: userinfo@host:port?query#fragment */
    splitURI(uri) {
      let fragment = '';
      const hashIdx = uri.indexOf('#');
      if (hashIdx !== -1) {
        fragment = decodeURIComponent(uri.substring(hashIdx + 1));
        uri = uri.substring(0, hashIdx);
      }

      let query = '';
      const qIdx = uri.indexOf('?');
      if (qIdx !== -1) {
        query = uri.substring(qIdx + 1);
        uri = uri.substring(0, qIdx);
      }

      let userInfo = '';
      const atIdx = uri.indexOf('@');
      if (atIdx !== -1) {
        userInfo = uri.substring(0, atIdx);
        uri = uri.substring(atIdx + 1);
      }

      // host:port
      const lastColon = uri.lastIndexOf(':');
      let host, port;
      if (lastColon !== -1) {
        host = uri.substring(0, lastColon).replace(/^\[|\]$/g, '');
        port = parseInt(uri.substring(lastColon + 1)) || 443;
      } else {
        host = uri.replace(/^\[|\]$/g, '');
        port = 443;
      }

      const params = {};
      if (query) {
        for (const pair of query.split('&')) {
          const [k, ...v] = pair.split('=');
          params[decodeURIComponent(k)] = decodeURIComponent(v.join('='));
        }
      }

      return { userInfo, host, port, params, fragment };
    },

    parseVless(link) {
      const { userInfo, host, port, params } = this.splitURI(link.substring(8));
      const type = params.type || 'tcp';
      const security = params.security || 'tls';
      const flow = params.flow || '';
      const sni = params.sni || '';
      const fp = params.fp || '';

      const result = {
        type: 'vless',
        host, port, server_port: port,
        protocol_settings: { network: type, flow }
      };

      if (security === 'reality') {
        result.protocol_settings.tls = 2;
        result.protocol_settings.reality_settings = {
          server_name: params.sni || '',
          public_key: params.pbk || '',
          short_id: params.sid || ''
        };
        if (fp) result.protocol_settings.utls = { enabled: true, fingerprint: fp };
      } else if (security === 'tls') {
        result.protocol_settings.tls = 1;
        result.protocol_settings.tls_settings = { server_name: sni };
      } else {
        result.protocol_settings.tls = 0;
      }

      const ns = {};
      if (type === 'ws') { ns.path = params.path || '/'; ns.headers = { Host: params.host || host }; }
      else if (type === 'grpc') { ns.serviceName = params.serviceName || ''; }
      else if (type === 'xhttp') { ns.path = params.path || '/'; }
      else if (type === 'httpupgrade') { ns.path = params.path || '/'; ns.host = params.host || host; }
      if (Object.keys(ns).length) result.protocol_settings.network_settings = ns;

      return result;
    },

    parseVmess(link) {
      const json = JSON.parse(atob(link.substring(8)));
      if (!json) throw new Error('VMess Base64 解码失败');

      const host = json.add || '';
      const port = parseInt(json.port) || 443;
      const net = json.net || 'tcp';
      const tls = json.tls === 'tls' ? 1 : 0;

      const result = {
        type: 'vmess',
        host, port, server_port: port,
        protocol_settings: { tls, network: net }
      };

      if (tls && json.sni) {
        result.protocol_settings.tls_settings = { server_name: json.sni };
      }

      const ns = {};
      if (net === 'ws') { ns.path = json.path || '/'; ns.headers = { Host: json.host || host }; }
      else if (net === 'grpc') { ns.serviceName = json.path || ''; }
      else if (net === 'httpupgrade') { ns.path = json.path || '/'; ns.host = json.host || host; }
      if (Object.keys(ns).length) result.protocol_settings.network_settings = ns;

      return result;
    },

    parseTrojan(link) {
      const { host, port, params } = this.splitURI(link.substring(9));
      const type = params.type || 'tcp';
      const sni = params.sni || '';

      const result = {
        type: 'trojan',
        host, port, server_port: port,
        protocol_settings: { network: type, server_name: sni }
      };

      const ns = {};
      if (type === 'grpc') { ns.serviceName = params.serviceName || ''; }
      else if (type === 'ws') { ns.path = params.path || '/'; ns.headers = { Host: params.host || host }; }
      if (Object.keys(ns).length) result.protocol_settings.network_settings = ns;

      return result;
    },

    parseHysteria2(link) {
      const prefix = link.startsWith('hy2://') ? 6 : 12;
      const { host, port, params } = this.splitURI(link.substring(prefix));

      const result = {
        type: 'hysteria',
        host, port, server_port: port,
        protocol_settings: {
          version: 2,
          tls: { server_name: params.sni || '', allow_insecure: params.insecure === '1' }
        }
      };

      if (params.obfs) {
        result.protocol_settings.obfs = {
          open: true, type: params.obfs, password: params['obfs-password'] || ''
        };
      }
      return result;
    },

    parseTuic(link) {
      const { host, port, params } = this.splitURI(link.substring(7));
      return {
        type: 'tuic',
        host, port, server_port: port,
        protocol_settings: {
          version: 5,
          tls: { server_name: params.sni || '', allow_insecure: params.insecure === '1' },
          alpn: params.alpn || ''
        }
      };
    },

    parseAnytls(link) {
      const { host, port, params } = this.splitURI(link.substring(9));
      return {
        type: 'anytls',
        host, port, server_port: port,
        protocol_settings: {
          tls: { server_name: params.sni || '', allow_insecure: params.insecure === '1' }
        }
      };
    },

    /** 解析链接并填入表单 */
    async parse() {
      const input = document.getElementById('xbp-psl-input');
      const btn = document.getElementById('xbp-psl-btn');
      const msg = document.getElementById('xbp-psl-msg');
      const link = input?.value?.trim();

      if (!link) return;

      btn.disabled = true;
      btn.textContent = '解析中...';
      btn.style.opacity = '0.6';
      msg.style.display = 'none';

      try {
        // 直接在前端解析，不依赖后端 API（避免 Octane 缓存/路由问题）
        const data = this.parseLocally(link);

        if (!data) throw new Error('无数据返回');

        // 填入表单字段
        this.fillForm(data);

        msg.style.display = 'block';
        msg.style.color = '#16a34a';
        msg.textContent = '✓ 解析成功，已自动填入协议类型、地址、端口等';
        input.value = '';
      } catch (err) {
        msg.style.display = 'block';
        msg.style.color = '#dc2626';
        msg.textContent = '✗ ' + (err.message || '解析失败');
      } finally {
        btn.disabled = false;
        btn.textContent = '解析填入';
        btn.style.opacity = '1';
      }
    },

    /** 将解析数据填入 React 表单 */
    fillForm(data) {
      // 1. 选择协议类型 — 触发 Select 组件
      if (data.type) {
        this.setProtocolType(data.type);
      }

      // 2. 延迟填入其他字段（等协议类型切换完成）
      setTimeout(() => {
        if (data.host) this.setInputValue('host', data.host);
        if (data.port) this.setInputValue('port', data.port);
        if (data.server_port) this.setInputValue('server_port', data.server_port);

        // 3. 再延迟填入 protocol_settings
        setTimeout(() => {
          if (data.protocol_settings) {
            this.fillProtocolSettings(data.protocol_settings);
          }
        }, 300);
      }, 200);
    },

    /** 通过模拟 React 事件设置 input 值 */
    setInputValue(fieldName, value) {
      const dialog = document.querySelector('[role="dialog"]');
      if (!dialog) return;

      const inputs = dialog.querySelectorAll('input');
      for (const input of inputs) {
        const formItem = input.closest('.space-y-2') || input.closest('[class*="FormItem"]') || input.parentElement?.parentElement;
        if (!formItem) continue;

        const label = formItem.querySelector('label');
        const labelText = label?.textContent || '';

        let match = false;
        if (fieldName === 'host' && (labelText.includes('节点地址') || labelText.includes('地址') || input.placeholder?.includes('域名'))) match = true;
        if (fieldName === 'port' && labelText.includes('连接端口')) match = true;
        if (fieldName === 'server_port' && labelText.includes('服务端口')) match = true;

        if (match) {
          const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
            window.HTMLInputElement.prototype, 'value'
          ).set;
          nativeInputValueSetter.call(input, String(value));
          input.dispatchEvent(new Event('input', { bubbles: true }));
          input.dispatchEvent(new Event('change', { bubbles: true }));
          return;
        }
      }
    },

    /** 触发协议类型选择 */
    setProtocolType(type) {
      const dialog = document.querySelector('[role="dialog"]');
      if (!dialog) return;

      // 找到 Select trigger 按钮（协议类型选择器）
      const selectTrigger = dialog.querySelector('button[role="combobox"]');
      if (!selectTrigger) return;

      // 点击打开下拉
      selectTrigger.click();

      // 等待下拉菜单出现后选择对应项
      setTimeout(() => {
        const options = document.querySelectorAll('[role="option"]');
        for (const opt of options) {
          const optText = (opt.textContent || '').toLowerCase();
          if (optText.includes(type.toLowerCase()) ||
              opt.getAttribute('data-value') === type) {
            opt.click();
            return;
          }
        }
        // 如果没找到精确匹配，关闭下拉
        selectTrigger.click();
      }, 100);
    },

    /** 填入 protocol_settings 的各个子字段 */
    fillProtocolSettings(settings) {
      const dialog = document.querySelector('[role="dialog"]');
      if (!dialog) return;

      // protocol_settings 里的字段通常在 "协议配置" 区域
      // 遍历所有 input 和 select，根据 label 匹配填入

      const allInputs = dialog.querySelectorAll('input');
      const allSelects = dialog.querySelectorAll('select, button[role="combobox"]');

      // 递归展平 settings 为 label -> value 映射
      const flatSettings = {};
      this.flattenSettings(settings, flatSettings);

      console.log('[Xboard-Plus] 填入 protocol_settings:', flatSettings);

      for (const input of allInputs) {
        const formItem = input.closest('.space-y-2') || input.closest('[class*="FormItem"]') || input.parentElement?.parentElement;
        if (!formItem) continue;
        const label = formItem.querySelector('label');
        const labelText = (label?.textContent || '').toLowerCase();

        // 匹配常见字段
        for (const [key, value] of Object.entries(flatSettings)) {
          if (value === undefined || value === null || value === '') continue;
          const keyLower = key.toLowerCase();

          let match = false;
          if (keyLower === 'server_name' && (labelText.includes('sni') || labelText.includes('server_name') || labelText.includes('服务器名'))) match = true;
          if (keyLower === 'path' && labelText.includes('path')) match = true;
          if (keyLower === 'servicename' && labelText.includes('service')) match = true;
          if (keyLower === 'host' && labelText.includes('host') && !labelText.includes('节点')) match = true;
          if (keyLower === 'public_key' && (labelText.includes('public') || labelText.includes('pbk'))) match = true;
          if (keyLower === 'short_id' && (labelText.includes('short') || labelText.includes('sid'))) match = true;
          if (keyLower === 'fingerprint' && labelText.includes('fingerprint')) match = true;

          if (match) {
            const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
              window.HTMLInputElement.prototype, 'value'
            ).set;
            nativeInputValueSetter.call(input, String(value));
            input.dispatchEvent(new Event('input', { bubbles: true }));
            input.dispatchEvent(new Event('change', { bubbles: true }));
            break;
          }
        }
      }

      // 处理 select 类型的字段（如 network, tls 等）
      // 这些通常是 combobox，需要特殊处理
      this.setSelectFields(dialog, settings);
    },

    /** 展平嵌套的 settings 对象 */
    flattenSettings(obj, result, prefix) {
      for (const [key, value] of Object.entries(obj)) {
        if (value && typeof value === 'object' && !Array.isArray(value)) {
          this.flattenSettings(value, result, key);
        } else {
          result[key] = value;
        }
      }
    },

    /** 处理 select/combobox 类型字段 */
    setSelectFields(dialog, settings) {
      // network 类型选择
      if (settings.network) {
        const comboboxes = dialog.querySelectorAll('button[role="combobox"]');
        // 第二个 combobox 通常是 network 选择（第一个是协议类型）
        for (let i = 1; i < comboboxes.length; i++) {
          const cb = comboboxes[i];
          const formItem = cb.closest('.space-y-2') || cb.closest('[class*="FormItem"]') || cb.parentElement?.parentElement;
          const label = formItem?.querySelector('label');
          const labelText = (label?.textContent || '').toLowerCase();

          if (labelText.includes('传输') || labelText.includes('network') || labelText.includes('transport')) {
            cb.click();
            setTimeout(() => {
              const options = document.querySelectorAll('[role="option"]');
              let found = false;
              for (const opt of options) {
                if ((opt.textContent || '').toLowerCase().includes(settings.network.toLowerCase())) {
                  opt.click();
                  found = true;
                  break;
                }
              }
              if (!found) cb.click(); // 关闭下拉
            }, 100);
            break;
          }
        }
      }
    },

    /** 监听节点弹窗打开，注入 UI */
    observe() {
      const observer = new MutationObserver(() => {
        const dialog = document.querySelector('[role="dialog"]');
        if (!dialog) {
          this.injected = false;
          return;
        }

        // 检查是否是节点表单弹窗（通过标题文字判断）
        const title = dialog.querySelector('h2, [class*="DialogTitle"]');
        if (!title) return;
        const titleText = title.textContent || '';
        // 匹配中英文的添加/新建/编辑节点标题
        if (!titleText.includes('节点') && !titleText.toLowerCase().includes('node') && !titleText.toLowerCase().includes('server')) return;

        // 已注入则跳过
        if (dialog.querySelector('#xbp-share-link-parser')) return;

        // 找到表单滚动区域
        const scrollArea = dialog.querySelector('[class*="overflow-y-auto"]')
          || dialog.querySelector('[class*="scroll"]')
          || dialog.querySelector('form');
        if (!scrollArea) return;

        const firstChild = scrollArea.firstElementChild;
        if (!firstChild) return;

        // 注入 UI
        const ui = this.createUI();
        scrollArea.insertBefore(ui, firstChild);

        // 绑定事件
        document.getElementById('xbp-psl-btn')?.addEventListener('click', () => this.parse());
        document.getElementById('xbp-psl-input')?.addEventListener('keydown', (e) => {
          if (e.key === 'Enter') { e.preventDefault(); this.parse(); }
        });

        this.injected = true;
        console.log('[Xboard-Plus] 分享链接解析器已注入到节点弹窗');
      });

      observer.observe(document.body, { childList: true, subtree: true });
    }
  };

  // ============================================================
  // 启动
  // ============================================================

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  function init() {
    ShareLinkParser.observe();
    console.log('[Xboard-Plus] 插件系统已加载');
  }

})();
