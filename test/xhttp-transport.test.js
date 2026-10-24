import { describe, it, expect } from 'vitest';
import yaml from 'js-yaml';
import { ClashConfigBuilder } from '../src/builders/ClashConfigBuilder.js';
import { SingboxConfigBuilder } from '../src/builders/SingboxConfigBuilder.js';
import { parseVless } from '../src/parsers/protocols/vlessParser.js';

const UUID = '11111111-2222-4333-8444-555555555555';
const HOST = 'example.com';
const XHTTP_URI =
    `vless://${UUID}@${HOST}:443?encryption=none&security=tls&sni=${HOST}&fp=chrome` +
    `&type=xhttp&host=${HOST}&path=%2Frandom-path&mode=auto` +
    `&extra=${encodeURIComponent('{"xPaddingBytes":"100-1000"}')}#v2net-xhttp`;

describe('VLESS XHTTP transport', () => {
    it('parses the xhttp fields from a share link', () => {
        const parsed = parseVless(XHTTP_URI);

        expect(parsed.transport).toMatchObject({
            type: 'xhttp',
            path: '/random-path',
            mode: 'auto',
            x_padding_bytes: '100-1000',
        });
        expect(parsed.transport.headers).toEqual({ host: HOST });
    });

    it('emits Mihomo xhttp-opts in the Clash config', async () => {
        const builder = new ClashConfigBuilder(XHTTP_URI, 'minimal', [], null, 'zh-CN', 'mihomo');
        const built = yaml.load(await builder.build());
        const proxy = (built.proxies || []).find((item) => item.name === 'v2net-xhttp');

        expect(proxy).toBeDefined();
        expect(proxy.network).toBe('xhttp');
        expect(proxy['xhttp-opts']).toMatchObject({
            path: '/random-path',
            host: HOST,
            mode: 'auto',
            'x-padding-bytes': '100-1000',
        });
    });

    it('drops xhttp nodes from the sing-box config', async () => {
        const builder = new SingboxConfigBuilder(XHTTP_URI, 'minimal', [], null, 'zh-CN', 'sing-box');
        const built = await builder.build();
        const config = typeof built === 'string' ? JSON.parse(built) : built;

        expect(JSON.stringify(config)).not.toContain('xhttp');
    });
});
