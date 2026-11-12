// SPDX-License-Identifier: Apache-2.0
'use strict';
'require view';
'require form';
'require rpc';
'require ui';
'require poll';
'require tools.widgets as widgets';

const callStatus = rpc.declare({
	object: 'luci.snort',
	method: 'status',
	expect: { }
});

const callService = rpc.declare({
	object: 'luci.snort',
	method: 'service',
	params: [ 'action' ],
	expect: { }
});

const callUpdateRules = rpc.declare({
	object: 'luci.snort',
	method: 'update_rules',
	expect: { }
});

function fmtSize(bytes) {
	return '%1024.2mB'.format(bytes || 0);
}

function statusRow(label, value) {
	return E('tr', { 'class': 'tr' }, [
		E('td', { 'class': 'td left', 'width': '33%' }, [ label ]),
		E('td', { 'class': 'td left' }, [ value ])
	]);
}

function renderStatus(st) {
	let state;

	if (st.updating)
		state = E('span', { 'class': 'label notice' }, [ _('Updating rules…') ]);
	else if (st.running)
		state = E('span', { 'class': 'label success' }, [ _('Running') ]);
	else if (st.enabled)
		state = E('span', { 'class': 'label warning' }, [ _('Enabled, not running') ]);
	else
		state = E('span', { 'class': 'label' }, [ _('Stopped') ]);

	const rows = [
		statusRow(_('Status'), state),
		statusRow(_('Snort version'), st.version || '-'),
		statusRow(_('Mode / interface'), '%s / %s'.format((st.mode || 'ids').toUpperCase(), st.interface || '-')),
		statusRow(_('Active rules'), '%d%s'.format(st.rules || 0, st.local_rules ? _(' (incl. local rules)') : '')),
		statusRow(_('Logged alerts'), '%d (%s)'.format(st.alerts_total || 0, fmtSize(st.alert_file_size))),
		statusRow(_('Memory (RSS)'), st.rss_kb ? fmtSize(st.rss_kb * 1024) : '-')
	];

	if (st.update_log)
		rows.push(statusRow(_('Last rule update'), E('pre', { 'style': 'margin:0;white-space:pre-wrap' }, [ st.update_log ])));

	return E('table', { 'class': 'table' }, rows);
}

function serviceAction(action) {
	return callService(action).then(function(res) {
		if (!res || !res.result)
			ui.addNotification(null, E('p', [ _('Command failed: %s').format(res && res.error || '?') ]), 'danger');
		else
			ui.addNotification(null, E('p', [ _('Snort %s requested. Loading the rules can take 30–60 seconds.').format(action) ]), 'info');
	});
}

return view.extend({
	load: function() {
		return callStatus();
	},

	render: function(st) {
		const statusNode = E('div', { 'id': 'snort-status' }, [ renderStatus(st || {}) ]);

		poll.add(function() {
			return callStatus().then(function(s) {
				const node = document.getElementById('snort-status');
				if (node)
					node.replaceChildren(renderStatus(s || {}));
			});
		}, 10);

		const buttons = E('div', { 'class': 'cbi-page-actions', 'style': 'text-align:left' }, [
			E('button', { 'class': 'btn cbi-button cbi-button-positive', 'click': ui.createHandlerFn(this, serviceAction, 'start') }, [ _('Start') ]), ' ',
			E('button', { 'class': 'btn cbi-button cbi-button-negative', 'click': ui.createHandlerFn(this, serviceAction, 'stop') }, [ _('Stop') ]), ' ',
			E('button', { 'class': 'btn cbi-button cbi-button-action', 'click': ui.createHandlerFn(this, serviceAction, 'restart') }, [ _('Restart') ]), ' ',
			E('button', {
				'class': 'btn cbi-button cbi-button-apply',
				'click': ui.createHandlerFn(this, function() {
					return callUpdateRules().then(function(res) {
						if (res && res.result)
							ui.addNotification(null, E('p', [ _('Rule update started. Snort restarts automatically when it finishes.') ]), 'info');
						else
							ui.addNotification(null, E('p', [ _('Rule update not started: %s').format(res && res.error || '?') ]), 'warning');
					});
				})
			}, [ _('Update rules') ])
		]);

		const m = new form.Map('snort', _('Snort IDS'),
			_('Snort 3 inspects traffic on the selected interface and logs alerts for matching rules. ' +
			  'In IDS mode it only observes; IPS mode places Snort inline and can block traffic.'));

		const s = m.section(form.NamedSection, 'snort', 'snort', _('Settings'));
		s.addremove = false;
		let o;

		o = s.option(form.Flag, 'enabled', _('Enabled'));
		o.rmempty = false;

		o = s.option(form.ListValue, 'mode', _('Mode'));
		o.value('ids', _('IDS – detect and alert only'));
		o.value('ips', _('IPS – inline, can block traffic'));
		o.default = 'ids';

		o = s.option(form.ListValue, 'method', _('Capture method'),
			_('IDS works with pcap or afpacket. IPS requires nfq (netfilter queue).'));
		o.value('pcap', 'pcap');
		o.value('afpacket', 'afpacket');
		o.value('nfq', 'nfq');
		o.default = 'pcap';

		o = s.option(form.ListValue, 'action', _('IPS action'),
			_('How matching traffic is handled in IPS mode. "default" uses each rule\'s own action.'));
		o.value('default', _('default'));
		o.value('alert', _('alert only'));
		o.value('block', _('block'));
		o.value('drop', _('drop'));
		o.value('reject', _('reject'));
		o.default = 'default';
		o.depends('mode', 'ips');

		o = s.option(widgets.DeviceSelect, 'interface', _('Interface'),
			_('Network device to monitor (pcap/afpacket). Busy gigabit links can exceed what Snort can inspect on small routers.'));
		o.noaliases = true;
		o.nocreate = true;
		o.depends('method', 'pcap');
		o.depends('method', 'afpacket');

		o = s.option(form.Value, 'home_net', _('Home networks'),
			_('Space-separated list of your own networks, used as $HOME_NET by the rules.'));
		o.placeholder = '192.168.1.0/24 10.0.0.0/8';

		o = s.option(form.Value, 'external_net', _('External networks'),
			_('Used as $EXTERNAL_NET. "any" is usually correct.'));
		o.placeholder = 'any';

		o = s.option(form.Value, 'oinkcode', _('Oinkcode'),
			_('Optional snort.org oinkcode for the registered ruleset. Leave empty to use the community rules.'));
		o.password = true;

		o = s.option(form.Flag, 'logging', _('Log alerts to file'),
			_('Writes alerts as JSON, which the Alerts page reads.'));
		o.default = '1';

		o = s.option(form.Value, 'include', _('Include file'),
			_('Optional Lua file appended to the generated configuration, e.g. for suppress lists or alert_syslog.'));
		o.placeholder = '/etc/snort/local.lua';

		o = s.option(form.Value, 'log_dir', _('Log directory'),
			_('Default /var/log is in RAM and cleared on reboot.'));
		o.placeholder = '/var/log';

		o = s.option(form.Flag, 'manual', _('Manual configuration'),
			_('Ignore these settings and use /etc/snort/snort.lua as-is.'));
		o.default = '0';

		return m.render().then(function(mapEl) {
			const statusSection = E('div', { 'class': 'cbi-section' }, [
				E('h3', [ _('Status') ]),
				statusNode,
				buttons
			]);
			const firstSection = mapEl.querySelector('.cbi-section');

			if (firstSection)
				firstSection.parentNode.insertBefore(statusSection, firstSection);
			else
				mapEl.appendChild(statusSection);

			return mapEl;
		});
	}
});
