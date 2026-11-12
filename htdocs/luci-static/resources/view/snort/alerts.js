// SPDX-License-Identifier: Apache-2.0
'use strict';
'require view';
'require rpc';
'require ui';
'require poll';

const callSummary = rpc.declare({
	object: 'luci.snort',
	method: 'summary',
	params: [ 'lines', 'top', 'recent' ],
	expect: { }
});

const callClear = rpc.declare({
	object: 'luci.snort',
	method: 'clear_alerts',
	expect: { }
});

let lines = 5000;
let filter = '';
let lastData = null;

function ruleId(a) {
	return '%d:%d'.format(a.gid || 1, a.sid || 0);
}

function hostList(list, total) {
	const shown = (list || []).join(', ');
	return (total > (list || []).length) ? '%s (+%d)'.format(shown, total - list.length) : shown;
}

function endpoint(ip, port) {
	if (!ip)
		return '-';
	return port ? '%s:%d'.format(ip.indexOf(':') >= 0 ? '[' + ip + ']' : ip, port) : ip;
}

function matches(fields) {
	if (!filter)
		return true;
	const needle = filter.toLowerCase();
	return fields.some(function(f) { return String(f || '').toLowerCase().indexOf(needle) >= 0; });
}

function titles(cols) {
	return E('tr', { 'class': 'tr table-titles' }, cols.map(function(c) {
		return E('th', { 'class': 'th' }, [ c ]);
	}));
}

function updateTables(data) {
	data = lastData = data || {};

	const rules = (data.rules || []).filter(function(r) {
		return matches([ ruleId(r), r.msg, (r.sources || []).join(' '), (r.targets || []).join(' ') ]);
	}).map(function(r) {
		return [
			r.count,
			ruleId(r),
			r.msg,
			hostList(r.sources, r.source_count),
			hostList(r.targets, r.target_count),
			r.last || '-'
		];
	});

	const sources = (data.sources || []).filter(function(s) {
		return matches([ s.addr ]);
	}).map(function(s) {
		return [ s.count, s.addr ];
	});

	const recent = (data.recent || []).filter(function(a) {
		return matches([ ruleId(a), a.msg, a.src, a.dst, a.proto ]);
	}).map(function(a) {
		return [
			a.timestamp || '-',
			ruleId(a),
			a.msg,
			a.proto || '-',
			endpoint(a.src, a.sport),
			endpoint(a.dst, a.dport),
			a.action || '-'
		];
	});

	cbi_update_table('#snort-rules', rules, E('em', [ _('No alerts.') ]));
	cbi_update_table('#snort-sources', sources, E('em', [ _('No alerts.') ]));
	cbi_update_table('#snort-recent', recent, E('em', [ _('No alerts.') ]));

	const info = document.getElementById('snort-analysed');
	if (info)
		info.textContent = _('Analysed the last %d logged alerts.').format(data.analysed || 0);
}

function refresh() {
	return callSummary(lines, 25, 100).then(updateTables);
}

return view.extend({
	load: function() {
		return callSummary(lines, 25, 100);
	},

	render: function(data) {
		const linesSelect = E('select', {
			'class': 'cbi-input-select',
			'change': function(ev) { lines = +ev.target.value; refresh(); }
		}, [ 1000, 5000, 20000, 50000 ].map(function(n) {
			return E('option', { 'value': n, 'selected': n == lines ? '' : null }, [ _('last %d alerts').format(n) ]);
		}));

		const filterInput = E('input', {
			'class': 'cbi-input-text',
			'type': 'text',
			'placeholder': _('Filter by IP, SID or message…'),
			'keyup': function(ev) { filter = ev.target.value.trim(); updateTables(lastData); }
		});

		const controls = E('div', { 'class': 'cbi-section' }, [
			E('div', { 'style': 'display:flex;gap:.5em;flex-wrap:wrap;align-items:center' }, [
				linesSelect,
				filterInput,
				E('button', { 'class': 'btn cbi-button cbi-button-action', 'click': ui.createHandlerFn(this, refresh) }, [ _('Refresh') ]),
				E('button', {
					'class': 'btn cbi-button cbi-button-negative',
					'click': ui.createHandlerFn(this, function() {
						if (!confirm(_('Delete all logged alerts?')))
							return;
						return callClear().then(refresh);
					})
				}, [ _('Clear alerts') ])
			]),
			E('p', { 'id': 'snort-analysed', 'class': 'cbi-section-descr' }, [ '' ])
		]);

		const view = E([], [
			E('h2', [ _('Snort IDS – Alerts') ]),
			controls,
			E('div', { 'class': 'cbi-section' }, [
				E('h3', [ _('Top rules') ]),
				E('table', { 'class': 'table', 'id': 'snort-rules' }, [
					titles([ _('Count'), _('Rule'), _('Message'), _('Sources'), _('Destinations'), _('Last seen') ])
				])
			]),
			E('div', { 'class': 'cbi-section' }, [
				E('h3', [ _('Top sources') ]),
				E('table', { 'class': 'table', 'id': 'snort-sources' }, [
					titles([ _('Count'), _('Source address') ])
				])
			]),
			E('div', { 'class': 'cbi-section' }, [
				E('h3', [ _('Recent alerts') ]),
				E('table', { 'class': 'table', 'id': 'snort-recent' }, [
					titles([ _('Time'), _('Rule'), _('Message'), _('Proto'), _('Source'), _('Destination'), _('Action') ])
				])
			])
		]);

		requestAnimationFrame(function() { updateTables(data); });
		poll.add(refresh, 30);

		return view;
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
