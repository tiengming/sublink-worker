import { describe, it, expect } from 'vitest';
import yaml from 'js-yaml';
import { ClashConfigBuilder } from '../src/builders/ClashConfigBuilder.js';
import { SingboxConfigBuilder } from '../src/builders/SingboxConfigBuilder.js';

const URI =
    'vless://11111111-2222-4333-8444-555555555555@example.com:443' +
    '?encryption=none&security=tls&sni=example.com&type=xhttp&host=example.com&path=%2Fx&mode=auto#x';

describe('Tailscale direct rules', () => {
    it('uses logical rules only for mihomo-family clients', async () => {
        const builder = new ClashConfigBuilder(URI, 'minimal', [], null, 'zh-CN', 'mihomo');
        const config = yaml.load(await builder.build());

        expect(config['find-process-mode']).toBe('always');
        expect(config.rules.slice(0, 3)).toEqual([
            'AND,((NETWORK,UDP),(PROCESS-NAME,tailscaled)),DIRECT',
            'AND,((NETWORK,UDP),(SRC-PORT,41641)),DIRECT',
            'IP-CIDR,100.64.0.0/10,DIRECT,no-resolve',
        ]);
    });

    it('keeps legacy Clash clients parseable (no AND rules)', async () => {
        const builder = new ClashConfigBuilder(URI, 'minimal', [], null, 'zh-CN', 'clashforwindows');
        const config = yaml.load(await builder.build());

        expect(config['find-process-mode']).toBeUndefined();
        expect(config.rules[0]).toBe('IP-CIDR,100.64.0.0/10,DIRECT,no-resolve');
        expect(config.rules.some((rule) => String(rule).startsWith('AND,'))).toBe(false);
    });

    it('emits source_port as an array for sing-box', async () => {
        const builder = new SingboxConfigBuilder(URI, 'minimal', [], null, 'zh-CN', 'sing-box');
        const built = await builder.build();
        const config = typeof built === 'string' ? JSON.parse(built) : built;

        const rules = config.route.rules;
        expect(rules[0]).toEqual({ action: 'sniff' });
        expect(rules[1]).toEqual({ network: 'udp', process_name: ['tailscaled'], outbound: 'DIRECT' });
        expect(rules[2]).toEqual({ network: 'udp', source_port: [41641], outbound: 'DIRECT' });
        expect(rules[3]).toEqual({ ip_cidr: ['100.64.0.0/10'], outbound: 'DIRECT' });
    });
});
