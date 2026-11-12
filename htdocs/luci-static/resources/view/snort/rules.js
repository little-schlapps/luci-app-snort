// SPDX-License-Identifier: Apache-2.0
'use strict';
'require view';
'require rpc';
'require ui';

const callGetLocal = rpc.declare({
	object: 'luci.snort',
	method: 'get_local_rules',
	expect: { content: '' }
});

const callSetLocal = rpc.declare({
	object: 'luci.snort',
	method: 'set_local_rules',
	params: [ 'content', 'restart' ],
	expect: { }
});

const EXAMPLE =
	'# One rule per line. Use SIDs of 1000000 and above for your own rules.\n' +
	'# Example: alert on Modbus/TCP traffic from the IoT network\n' +
	'# alert tcp 10.255.254.0/24 any -> any 502 ( msg:"IoT host talking Modbus"; sid:1000010; rev:1; )\n';

return view.extend({
	load: function() {
		return callGetLocal();
	},

	handleSave: function(ev) {
		const content = document.getElementById('snort-local-rules').value;

		return callSetLocal(content, true).then(function(res) {
			if (res && res.result)
				ui.addNotification(null, E('p', [ _('Local rules saved. Snort is restarting; loading takes 30–60 seconds. Check the Overview page for status.') ]), 'info');
			else
				ui.addNotification(null, E('p', [ _('Saving failed: %s').format(res && res.error || '?') ]), 'danger');
		});
	},

	render: function(content) {
		return E([], [
			E('h2', [ _('Snort IDS – Local Rules') ]),
			E('div', { 'class': 'cbi-section-descr' }, [
				_('Your own rules, stored in /etc/snort/local.rules and loaded together with the downloaded ruleset. ' +
				  'They are kept when rules are updated from this interface. ' +
				  'A syntax error stops Snort from starting, so check the Overview page after saving.')
			]),
			E('div', { 'class': 'cbi-section' }, [
				E('textarea', {
					'id': 'snort-local-rules',
					'class': 'cbi-input-textarea',
					'style': 'width:100%;font-family:monospace',
					'rows': 20,
					'wrap': 'off',
					'spellcheck': 'false',
					'placeholder': EXAMPLE
				}, [ content || '' ])
			])
		]);
	},

	handleSaveApply: null,
	handleReset: null
});
