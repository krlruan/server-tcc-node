// ---------------------------------------------------------------------------
// phish-score.js
// Porta FIEL do ScanViewModel.kt do PhishScan (Khalique Khan, 2023).
// Módulo puro (sem APIs do Chrome): roda no service worker e também no Node.
//
// Regra de ouro: cada verificação reproduz o que o código Kotlin FAZ, não o que
// o artigo DESCREVE. Quirks do original preservados de propósito:
//   - DNS: checkDNSRecord() passa a URL inteira a InetAddress.getByName(), que
//     sempre lança UnknownHostException -> +5 em TODA URL.
//   - checkProtocolInDomain(): `!startsWith("http://") || !startsWith("https://")`
//     é sempre verdadeiro -> +2 em TODA URL.
//   - checkForAtSymbol(): compara Char com String ("@") -> nunca conta.
//   - checkDomainCreationDate(): depende de um header "Creation-Date" que não
//     existe em HTTP -> nunca conta.
//   - checkDomainAge(): é assíncrono (Retrofit enqueue); o veredito é calculado
//     antes do callback -> a idade NÃO entra no veredito (ver opcoes.contarIdade).
//   - checkForIdnAndHomographAttacks(): IDN.toASCII(url) recebe a URL inteira e
//     lança IllegalArgumentException se algum trecho entre pontos tiver > 63
//     caracteres (ou vazio no meio). Sem try/catch: o app não gera veredito
//     ("Unable to Verify" da Tabela 4). Aqui vira { inverificavel: true }.
//   - Encurtadores: expandURL() é assíncrono e devolve "" -> o original aborta
//     com erro. Aqui, sem opcoes.urlExpandida, também vira inverificavel.
//   - segregateUrl(): hosts com 1 ou 2 rótulos falham no cast para ArrayList
//     (exceção engolida), então só hosts com 3+ rótulos geram "subdomínios".
//
// Premissa (NÃO está no código enviado): URL sem esquema recebe "http://" antes
// de pontuar (o artigo mostra QR com "www.monster.pay.pal.xyz/" e pontua).
//
// Etapas:
//   1) avaliarLocal(url, opcoes)   -> tudo que dá para calcular sem rede
//   2) aplicarRede(local, rede, opcoes) -> SSL, redirecionamento (e idade, opcional)
// ---------------------------------------------------------------------------

// Cortes do código original: score <= 12 NotPhishing; 12 < score <= 25 Maybe; > 25 Phishing.
export const LIMIAR_SUSPEITO = 12; // score > 12 é suspeito
export const LIMIAR_PHISHING = 25; // score > 25 é phishing

// Pontos máximos de cada regra no código original (algumas valem menos, ex.: ssl 2.5).
export const PESOS = {
  idn: 5,
  caracteres: 5,
  estrutura: 5,
  tamanho: 5,
  arroba: 5, // nunca dispara no original
  redirecionamento: 3,
  encurtador: 2,
  protocoloNoDominio: 2,
  tamanhoDominio: 3,
  pontos: 3,
  palavraMedia: 2,
  palavraMaior: 3,
  idadeDominio: 5,
  dns: 5,
  similaridade: 15,
  subdominio: 10,
  extensao: 10,
  ssl: 2.5,
  ip: 5,
};

// ---------------------------------------------------------------------------
// Listas do código original
// ---------------------------------------------------------------------------

const ENCURTADORES = ["bit.ly", "tinyurl.com", "goo.gl", "BL.INK", "Ow.ly"]; // contains(), diferencia maiúsculas

const DOMINIOS_LEGITIMOS = ["twitter.com", "google.com", "facebook.com", "paypal.com", "payment", "amazon"];

const TLDS_SUSPEITOS = new Set([
  "xyz", "info", "biz", "top", "online", "club", "site", "ga", "cf", "tk", "org", "ml", "pw", "icu",
]);

const CARACTERES_SUSPEITOS = [
  "@", "%", "!", "#", "$", "&", "*", "(", ")", "[", "]", "{", "}", "<", ">", "|", "\\",
  "/", "?", ":", ";", "'", '"', "`", "~", "+", "=", "^",
];

// ---------------------------------------------------------------------------
// Utilidades de host (não fazem parte da pontuação; usadas pela extensão)
// ---------------------------------------------------------------------------

const SLDS_COMPOSTOS = new Set(["com", "net", "org", "gov", "edu", "co", "ac", "mil"]);

// [nome da marca, domínios oficiais]
const MARCAS = [
  ["paypal", ["paypal.com", "paypal.com.br", "paypal.me"]],
  ["amazon", ["amazon.com", "amazon.com.br", "amazon.co.uk", "amazon.de"]],
  ["google", ["google.com", "google.com.br", "gmail.com", "goo.gl", "gstatic.com", "googleapis.com"]],
  ["youtube", ["youtube.com", "youtu.be"]],
  ["microsoft", ["microsoft.com", "microsoftonline.com", "live.com", "office.com", "outlook.com"]],
  ["apple", ["apple.com", "icloud.com"]],
  ["facebook", ["facebook.com", "fb.com"]],
  ["instagram", ["instagram.com"]],
  ["whatsapp", ["whatsapp.com", "whatsapp.net"]],
  ["netflix", ["netflix.com"]],
  ["linkedin", ["linkedin.com"]],
  ["twitter", ["twitter.com", "x.com"]],
  ["telegram", ["telegram.org", "t.me"]],
  ["discord", ["discord.com", "discord.gg"]],
  ["tiktok", ["tiktok.com"]],
  ["spotify", ["spotify.com"]],
  ["dropbox", ["dropbox.com"]],
  ["github", ["github.com"]],
  ["ebay", ["ebay.com"]],
  ["binance", ["binance.com"]],
  ["coinbase", ["coinbase.com"]],
  ["aliexpress", ["aliexpress.com"]],
  ["shopee", ["shopee.com.br", "shopee.com"]],
  ["mercadolivre", ["mercadolivre.com.br", "mercadolibre.com"]],
  ["mercadopago", ["mercadopago.com.br", "mercadopago.com"]],
  ["magazineluiza", ["magazineluiza.com.br", "magalu.com.br"]],
  ["americanas", ["americanas.com.br"]],
  ["casasbahia", ["casasbahia.com.br"]],
  ["itau", ["itau.com.br", "itau.com"]],
  ["bradesco", ["bradesco.com.br"]],
  ["santander", ["santander.com.br", "santander.com"]],
  ["caixa", ["caixa.gov.br"]],
  ["nubank", ["nubank.com.br"]],
  ["sicredi", ["sicredi.com.br"]],
  ["sicoob", ["sicoob.com.br"]],
  ["bancointer", ["bancointer.com.br"]],
  ["pagseguro", ["pagseguro.uol.com.br", "pagseguro.com.br"]],
  ["picpay", ["picpay.com"]],
  ["serasa", ["serasa.com.br", "serasaexperian.com.br"]],
  ["correios", ["correios.com.br"]],
];

const ehIp = (host) => /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith("[");

const ehHostLocal = (host) =>
  host === "localhost" ||
  host.endsWith(".localhost") ||
  /^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host);

export function dominioRegistravel(host) {
  const p = host.split(".");
  if (p.length <= 2) return host;
  const tld = p[p.length - 1];
  const sld = p[p.length - 2];
  return tld.length === 2 && SLDS_COMPOSTOS.has(sld) ? p.slice(-3).join(".") : p.slice(-2).join(".");
}

const noDominio = (host, d) => host === d || host.endsWith("." + d);

export const ehSiteOficial = (host) => MARCAS.some(([, doms]) => doms.some((d) => noDominio(host, d)));

// ---------------------------------------------------------------------------
// Emulação do que o Java/Kotlin faz com a URL
// ---------------------------------------------------------------------------

class FalhaOriginal extends Error {}

/** URL sem esquema ganha "http://" (premissa; ver cabeçalho). */
export function normalizarUrl(s) {
  const t = String(s).trim();
  return /^[a-z][a-z0-9+.-]*:/i.test(t) ? t : "http://" + t;
}

/** java.net.URI(url) lança URISyntaxException nestes casos (segregateUrl não protege essa linha). */
function validarUri(url) {
  if (/[\s"<>\\^`{|}]/.test(url) || /%(?![0-9a-fA-F]{2})/.test(url) || (url.match(/#/g) || []).length > 1) {
    throw new FalhaOriginal("URI(url) lançou URISyntaxException (caractere inválido)");
  }
}

const HOST_NOME = /^([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\.)*[A-Za-z]([A-Za-z0-9-]*[A-Za-z0-9])?\.?$/;
const HOST_IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

/** uri.host do Java: sem normalizar maiúsculas; null (-> "") se o host não for válido. */
function hostJava(url) {
  const m = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/([^/?#]*)/.exec(url);
  if (!m) return "";
  let a = m[1].slice(m[1].lastIndexOf("@") + 1);
  if (a.startsWith("[")) {
    const f = a.indexOf("]");
    return f > 0 ? a.slice(0, f + 1) : "";
  }
  a = a.replace(/:\d*$/, "");
  return HOST_NOME.test(a) || HOST_IPV4.test(a) ? a : "";
}

/** IDN.toASCII(url): lança IllegalArgumentException para rótulo > 63 ou vazio no meio. */
function idnParaAscii(url) {
  const rotulos = url.split(/[.\u3002\uFF0E\uFF61]/);
  rotulos.forEach((r, i) => {
    if (r.length > 63) throw new FalhaOriginal(`IDN.toASCII lançou exceção: trecho de ${r.length} caracteres entre pontos (limite 63)`);
    if (r.length === 0 && i < rotulos.length - 1) throw new FalhaOriginal("IDN.toASCII lançou exceção: rótulo vazio");
  });
}

/** calculateDomainSimilarity(): compara posição a posição; (iguais / tamanho do maior). */
function similaridadePosicional(d1, d2) {
  const maior = d1.length >= d2.length ? d1 : d2;
  const menor = d1.length < d2.length ? d1 : d2;
  let diff = 0;
  for (let i = 0; i < maior.length; i++) if (i >= menor.length || maior[i] !== menor[i]) diff++;
  return (maior.length - diff) / maior.length;
}

// ---------------------------------------------------------------------------
// API pública
// ---------------------------------------------------------------------------

const somar = (detalhes) => detalhes.reduce((t, d) => t + d.pontos, 0);
const unicos = (detalhes) => [...new Set(detalhes.map((d) => d.flag))];

function resultado(u, detalhes, extra = {}) {
  const host = u.hostname.toLowerCase().replace(/\.$/, "");
  const ip = ehIp(host);
  return {
    score: somar(detalhes),
    flags: unicos(detalhes),
    detalhes,
    host,
    registravel: ip ? host : dominioRegistravel(host),
    ehIp: ip,
    local: false,
    inverificavel: false,
    ...extra,
  };
}

/**
 * Tudo que o ScanViewModel calcula sem rede.
 * opcoes.urlExpandida: URL já expandida de um encurtador (o original não consegue; ver cabeçalho).
 * Retorna null se não for http(s). Se o original quebraria, retorna { inverificavel: true, motivo }.
 */
export function avaliarLocal(urlStr, opcoes = {}) {
  let alvo = normalizarUrl(urlStr);
  let u;
  try {
    u = new URL(alvo);
  } catch {
    return null;
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return null;

  const detalhes = [];
  const add = (flag, pontos) => detalhes.push({ flag, pontos });

  // isURLShortened(): +2 e tenta expandir
  if (ENCURTADORES.some((d) => alvo.includes(d))) {
    if (!opcoes.urlExpandida) {
      return resultado(u, [], {
        inverificavel: true,
        motivo: "URL encurtada: no original expandURL() é assíncrono e devolve vazio (erro, sem veredito)",
      });
    }
    add("encurtador", 2);
    alvo = normalizarUrl(opcoes.urlExpandida);
    try {
      u = new URL(alvo);
    } catch {
      return null;
    }
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
  }

  const hostWhatwg = u.hostname.toLowerCase().replace(/\.$/, "");
  if (ehHostLocal(hostWhatwg)) {
    return { score: 0, flags: [], detalhes: [], host: hostWhatwg, registravel: hostWhatwg, ehIp: false, local: true, inverificavel: false };
  }

  try {
    // segregateUrl()
    validarUri(alvo);
    const dominio = hostJava(alvo);
    const rotulos = dominio.split(".");
    // dropLast(1) as ArrayList só funciona com 3+ rótulos; senão ClassCastException engolida
    const subdominios = rotulos.length >= 3 ? rotulos.slice(0, -1).map((s) => s.toLowerCase()) : [];

    // domainSimilarity(): +15 por domínio da lista com similaridade >= 0.8
    for (const legitimo of DOMINIOS_LEGITIMOS) {
      if (similaridadePosicional(dominio, legitimo) >= 0.8) add("similaridade", 15);
    }

    // checkSubdomainAnomalies(): +10 por subdomínio fora de [a-zA-Z0-9-]+
    for (const s of subdominios) if (!/^[a-zA-Z0-9-]+$/.test(s)) add("subdominio", 10);

    // checkDomainSuspicion()
    const tld = dominio.includes(".") ? dominio.slice(dominio.lastIndexOf(".") + 1) : "";
    if (TLDS_SUSPEITOS.has(tld)) add("extensao", 10);

    // checkUrlValidity(): em http o original sempre soma 2,5; em https só se a conexão falhar (aplicarRede)
    if (u.protocol === "http:") add("ssl", 2.5);

    // checkForIdnAndHomographAttacks()
    idnParaAscii(alvo);
    if (/[^\x00-\x7f]/.test(alvo)) add("idn", 5);

    // checkForSuspiciousCharacters(): conta caracteres DISTINTOS presentes
    const distintos = CARACTERES_SUSPEITOS.filter((c) => alvo.includes(c)).length;
    if (distintos > 4) add("caracteres", 5);

    // checkForDirectIPAddressUsage()
    if (/\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(alvo)) add("ip", 5);

    // checkUrlStructureAndParameters()
    let suspeita = 0;
    const semHash = alvo.split("#")[0];
    const q = semHash.indexOf("?");
    if (q >= 0) {
      for (const par of semHash.slice(q + 1).split("&")) {
        const kv = par.split("=");
        if (kv.length !== 2 || !kv[0] || !kv[1]) suspeita++;
      }
    }
    if (suspeita > 3) add("estrutura", 5);
    else if (suspeita > 0) add("estrutura", suspeita);

    // checkUrlLength()
    if (alvo.length >= 70) add("tamanho", 5);
    else if (alvo.length >= 40) add("tamanho", 2);

    // checkForAtSymbol(): nunca dispara no original (Char.equals(String))

    // checkProtocolInDomain(): condição sempre verdadeira
    add("protocoloNoDominio", 2);

    // checkPrimaryDomainLength(): usa o host inteiro
    if (dominio.length > 14) add("tamanhoDominio", 3);
    else if (dominio.length >= 7) add("tamanhoDominio", 1);

    // checkNumberOfDots(): pontos na URL inteira
    if ((alvo.match(/\./g) || []).length > 4) add("pontos", 3);

    // calculateAverageWordLength() e checkLongestWordLength(): split("\\W+") mantém vazios
    const palavras = alvo.split(/\W+/);
    const media = palavras.reduce((s, w) => s + w.length, 0) / palavras.length;
    if (media > 6) add("palavraMedia", 2);
    if (Math.max(...palavras.map((w) => w.length)) > 15) add("palavraMaior", 3);

    // checkDomainCreationDate(): nunca dispara (header inexistente)

    // checkDNSRecord(): getByName(URL inteira) sempre falha
    add("dns", 5);
  } catch (e) {
    if (e instanceof FalhaOriginal) return resultado(u, [], { inverificavel: true, motivo: e.message });
    throw e;
  }

  return resultado(u, detalhes);
}

/**
 * Soma o que depende de rede.
 *   rede.ssl === false            -> handshake HTTPS falhou (https: +2,5)
 *   rede.redirecionamento === true -> resposta 3xx com Location (+3); com
 *                                     rede.redirecionaParaEncurtador === true (+2)
 *   rede.idade_dias               -> só conta se opcoes.contarIdade (padrão false: no original é assíncrono)
 *   rede.dns                      -> ignorado: o original nunca resolve DNS de verdade (+5 já está no local)
 */
export function aplicarRede(local, rede, opcoes = {}) {
  if (!local || local.local || local.inverificavel || !rede) return { ...local, rede: Boolean(rede) };

  const detalhes = [...local.detalhes];
  const tem = (f) => detalhes.some((d) => d.flag === f);

  if (rede.ssl === false && !tem("ssl")) detalhes.push({ flag: "ssl", pontos: 2.5 });
  if (rede.redirecionamento === true) {
    detalhes.push({ flag: "redirecionamento", pontos: 3 });
    if (rede.redirecionaParaEncurtador === true) detalhes.push({ flag: "redirecionamento", pontos: 2 });
  }
  if (opcoes.contarIdade && typeof rede.idade_dias === "number" && rede.idade_dias <= 360) {
    detalhes.push({ flag: "idadeDominio", pontos: 5 });
  }

  return { ...local, detalhes, flags: unicos(detalhes), score: somar(detalhes), rede: true };
}

/** 'safe' | 'suspicious' | 'dangerous' (NotPhishing / MaybePhishing / Phishing do original). */
export function classificar(score) {
  if (score <= LIMIAR_SUSPEITO) return "safe";
  if (score <= LIMIAR_PHISHING) return "suspicious";
  return "dangerous";
}
