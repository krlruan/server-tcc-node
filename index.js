const express = require('express');
const https = require('https');
const net = require('net'); // Módulo nativo para conexões TCP
const { URL } = require('url');

const app = express();
const PORT = 3000;

const ENCURTADORES_CONHECIDOS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 
    'buff.ly', 'adf.ly', 'bl.ink', 'lnkd.in', 'rebrand.ly', 'migre.me'
];

function extrairDominio(input) {
    try {
        let formatoUrl = input.includes('://') ? input : `http://${input}`;
        const meuUrl = new URL(formatoUrl);
        return meuUrl.hostname.replace('www.', '');
    } catch (e) {
        return input.replace('www.', '');
    }
}

function verificarSSL(dominio) {
    return new Promise((resolve) => {
        const agente = https.request({
            hostname: dominio,
            port: 443,
            method: 'HEAD',
            timeout: 3000
        }, () => {
            resolve(true);
        });

        agente.on('error', () => resolve(false));
        agente.on('timeout', () => {
            agente.destroy();
            resolve(false);
        });

        agente.end();
    });
}

app.get('/analisar', async (req, res) => {
    const { url } = req.query;
    if (!url) return res.status(400).json({ erro: 'Por favor, forneça o parâmetro ?url=' });

    const dominio = extrairDominio(url);
    const ehEncurtador = ENCURTADORES_CONHECIDOS.includes(dominio);

    try {
        // Executa SSL e a nossa função TCP customizada em paralelo
        const [temSsl] = await Promise.all([
            verificarSSL(dominio),
        ]);

        return res.json({
            dominio,
            encurtador_conhecido: ehEncurtador,
            possui_ssl: temSsl,
        });
    } catch (erro) {
        return res.status(500).json({ erro: erro.message });
    }
});

app.listen(PORT, () => {
    console.log(`API 100% nativa rodando em http://localhost:${PORT}`);
});
