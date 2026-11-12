// SPDX-License-Identifier: Apache-2.0
'use strict';
'require view';
'require rpc';
'require poll';

const callLog = rpc.declare({
	object: 'luci.snort',
	method: 'log',
	params: [ 'lines' ],
	expect: { log: '' }
});

function setLog(text) {
	const node = document.getElementById('snort-log');
	if (!node)
		return;

	const atBottom = node.scrollTop + node.clientHeight >= node.scrollHeight - 5;
	node.value = text || _('No Snort messages in the system log.');
	if (atBottom)
		node.scrollTop = node.scrollHeight;
}

return view.extend({
	load: function() {
		return callLog(500);
	},

	render: function(text) {
		const ta = E('textarea', {
			'id': 'snort-log',
			'class': 'cbi-input-textarea',
			'style': 'width:100%;font-family:monospace;font-size:12px',
			'rows': 30,
			'wrap': 'off',
			'readonly': 'readonly'
		});

		requestAnimationFrame(function() {
			setLog(text);
			ta.scrollTop = ta.scrollHeight;
		});

		poll.add(function() {
			return callLog(500).then(setLog);
		}, 10);

		return E([], [
			E('h2', [ _('Snort IDS – Log') ]),
			E('div', { 'class': 'cbi-section-descr' }, [
				_('Snort-related entries from the system log (alerts appear here when alert_syslog is enabled in the include file). Refreshes every 10 seconds.')
			]),
			E('div', { 'class': 'cbi-section' }, [ ta ])
		]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
