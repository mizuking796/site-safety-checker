(function() {
'use strict';

// ============================================================
// Config & Storage
// ============================================================
const STORAGE_KEY = 'ssc_config';
const DEFAULT_WORKER_URL = 'https://site-safety-checker.mizuki-tools.workers.dev';

function loadConfig() {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY)) || {}; } catch { return {}; }
}
function saveConfig(cfg) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(cfg));
}

function hasConsent() {
  return !!localStorage.getItem('ssc_consent');
}
function setConsent() {
  localStorage.setItem('ssc_consent', new Date().toISOString().slice(0, 10));
}

function loadSensitivity() {
  return localStorage.getItem('ssc_sensitivity') || 'standard';
}
function saveSensitivity(val) {
  localStorage.setItem('ssc_sensitivity', val);
}

// ============================================================
// Router
// ============================================================
const screens = ['screenConsent', 'screenSetup', 'screenCheck', 'screenResults', 'screenSettings'];

function showScreen(id) {
  screens.forEach(s => {
    const el = document.getElementById(s);
    if (el) el.hidden = (s !== id);
  });
}

// ============================================================
// URL Analyzer (client-side, no network)
// ============================================================
const UrlAnalyzer = {
  SUSPICIOUS_TLDS: ['xyz','top','icu','buzz','club','online','site','fun','monster','click',
    'link','work','rest','gq','ml','cf','ga','tk','pw','cc','ws','info','bid','stream','racing',
    'download','win','review','trade','loan','cricket','science','party','date'],

  BRANDS: ['amazon','rakuten','yahoo','google','apple','microsoft','facebook','instagram',
    'twitter','paypal','netflix','docomo','softbank','mercari','paypay',
    'smbc','mufg','mizuho','jpbank','aeon','familymart','lawson','uniqlo'],

  analyze(urlStr) {
    const result = {
      domain_trust: 100,
      tech_safety: 100,
      issues: []
    };

    let url;
    try { url = new URL(urlStr); } catch {
      return { domain_trust: 0, tech_safety: 0, issues: [{ title: '無効なURL', severity: 'critical' }] };
    }

    // HTTP check
    if (url.protocol === 'http:') {
      result.tech_safety -= 30;
      result.issues.push({ title: 'SSL未使用（HTTP）', severity: 'high', desc: '暗号化されていない通信です。' });
    }

    // IP address URL
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(url.hostname)) {
      result.domain_trust -= 40;
      result.issues.push({ title: 'IPアドレスURL', severity: 'high', desc: 'ドメイン名ではなくIPアドレスが使われています。' });
    }

    // Suspicious TLD
    const tld = url.hostname.split('.').pop().toLowerCase();
    if (this.SUSPICIOUS_TLDS.includes(tld)) {
      result.domain_trust -= 20;
      result.issues.push({ title: `不審なTLD (.${tld})`, severity: 'medium', desc: '詐欺サイトで多用されるトップレベルドメインです。' });
    }

    // Excessive subdomains
    const parts = url.hostname.split('.');
    if (parts.length > 4) {
      result.domain_trust -= 15;
      result.issues.push({ title: '過剰なサブドメイン', severity: 'medium', desc: `${parts.length}階層のサブドメインがあります。` });
    }

    // Brand typosquatting
    const hostLower = url.hostname.toLowerCase().replace(/[^a-z0-9]/g, '');
    for (const brand of this.BRANDS) {
      if (hostLower.includes(brand) && !url.hostname.endsWith('.' + brand + '.com') &&
          !url.hostname.endsWith('.' + brand + '.co.jp') && !url.hostname.endsWith('.' + brand + '.jp') &&
          url.hostname !== brand + '.com' && url.hostname !== brand + '.co.jp' && url.hostname !== brand + '.jp' &&
          url.hostname !== 'www.' + brand + '.com' && url.hostname !== 'www.' + brand + '.co.jp') {
        result.domain_trust -= 30;
        result.issues.push({
          title: `ブランド偽装の疑い（${brand}）`,
          severity: 'high',
          desc: `「${brand}」を含むが公式ドメインではありません。`
        });
        break;
      }
    }

    // IDN homograph — only flag if mixed scripts or resembles a known brand
    // Pure Japanese/Chinese/Korean IDN domains are legitimate (e.g. 君塚法律事務所.com)
    if (/xn--/.test(url.hostname)) {
      let decoded;
      try { decoded = new URL(urlStr).hostname; } catch { decoded = url.hostname; }
      // Check if it contains Latin characters mixed with non-Latin (homograph risk)
      const hasLatin = /[a-zA-Z]/.test(decoded.replace(/\.[a-z]+$/, ''));
      const hasNonLatin = /[^\x00-\x7F]/.test(decoded);
      if (hasLatin && hasNonLatin) {
        // Mixed scripts: possible homograph attack (e.g. аmazon.com with Cyrillic а)
        result.domain_trust -= 25;
        result.issues.push({ title: 'IDNホモグラフの疑い', severity: 'high', desc: 'ドメイン名にラテン文字と非ラテン文字が混在しています。ブランド偽装の可能性があります。' });
      }
      // Pure non-Latin IDN (Japanese, etc.) — no penalty, it's normal
    }

    // Suspicious path keywords
    const pathLower = (url.pathname + url.search).toLowerCase();
    const suspiciousPath = ['login','signin','verify','secure','account','update','confirm','banking','wallet'];
    const found = suspiciousPath.filter(k => pathLower.includes(k));
    if (found.length >= 2) {
      result.domain_trust -= 10;
      result.issues.push({ title: '不審なパスキーワード', severity: 'low', desc: `パスに「${found.join('」「')}」が含まれています。` });
    }

    // Long URL — check path length only (exclude query params like gclid, utm_*, fbclid)
    const pathLen = (url.origin + url.pathname).length;
    if (pathLen > 200) {
      result.domain_trust -= 5;
      result.issues.push({ title: '異常に長いURL', severity: 'low', desc: `パス長: ${pathLen}文字` });
    }

    // Clamp
    result.domain_trust = Math.max(0, Math.min(100, result.domain_trust));
    result.tech_safety = Math.max(0, Math.min(100, result.tech_safety));

    return result;
  }
};

// ============================================================
// HTML Content Extractor (DOMParser, client-side)
// ============================================================
const HtmlExtractor = {
  extract(html, baseUrl) {
    const parser = new DOMParser();
    const doc = parser.parseFromString(html, 'text/html');
    const result = {};

    // Title
    result.title = doc.title || '';

    // Meta
    result.meta = {};
    doc.querySelectorAll('meta').forEach(m => {
      const name = m.getAttribute('name') || m.getAttribute('property') || '';
      const content = m.getAttribute('content') || '';
      if (name && content) result.meta[name.toLowerCase()] = content.slice(0, 200);
    });

    // Headings
    result.headings = [];
    doc.querySelectorAll('h1,h2,h3').forEach(h => {
      const t = h.textContent.trim();
      if (t) result.headings.push(t.slice(0, 200));
    });
    result.headings = result.headings.slice(0, 20);

    // Body text: head 8000 chars + tail 2000 chars (for footer/operator info)
    const bodyTextFull = (doc.body ? doc.body.textContent : '').replace(/\s+/g, ' ').trim();
    if (bodyTextFull.length <= 10000) {
      result.bodyText = bodyTextFull;
    } else {
      const head = bodyTextFull.slice(0, 8000);
      const tail = bodyTextFull.slice(-2000);
      result.bodyText = head + '\n[...中略...]\n' + tail;
    }
    result._bodyTextFull = bodyTextFull; // keep full text for regex checks

    // Links analysis
    const links = Array.from(doc.querySelectorAll('a[href]'));
    const externalLinks = [];
    let host;
    try { host = new URL(baseUrl).hostname; } catch { host = ''; }
    links.forEach(a => {
      try {
        const href = new URL(a.href, baseUrl);
        if (href.hostname && href.hostname !== host) {
          externalLinks.push(href.hostname);
        }
      } catch {}
    });
    result.externalLinkCount = externalLinks.length;
    result.externalDomains = [...new Set(externalLinks)].slice(0, 20);

    // Forms
    const forms = doc.querySelectorAll('form');
    result.forms = [];
    forms.forEach(f => {
      const inputs = Array.from(f.querySelectorAll('input')).map(i => ({
        type: i.type || 'text',
        name: i.name || ''
      }));
      const hasPassword = inputs.some(i => i.type === 'password');
      const hasCard = inputs.some(i => /card|credit|cvv|ccv/i.test(i.name));
      result.forms.push({ action: f.action || '', method: f.method || 'get', hasPassword, hasCard, inputCount: inputs.length });
    });

    // Scripts analysis — only flag heavy obfuscation, not normal minified/analytics code
    const scripts = doc.querySelectorAll('script');
    let inlineScriptChars = 0;
    let obfuscationSuspect = false;
    scripts.forEach(s => {
      if (!s.src) {
        const code = s.textContent || '';
        inlineScriptChars += code.length;
        // Only flag if multiple suspicious patterns co-occur in the SAME script block
        // Single atob() or eval() is common in analytics/tag managers
        const suspiciousCount = [
          /eval\s*\(/.test(code),
          /atob\s*\(/.test(code),
          /fromCharCode/.test(code),
          /\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}/i.test(code), // 3+ hex escapes
          /\\u[0-9a-f]{4}.*\\u[0-9a-f]{4}.*\\u[0-9a-f]{4}/i.test(code), // 3+ unicode escapes
          /document\.write\s*\(/.test(code) && /unescape|decodeURI/.test(code),
        ].filter(Boolean).length;
        if (suspiciousCount >= 2) {
          obfuscationSuspect = true;
        }
      }
    });
    result.inlineScriptChars = inlineScriptChars;
    result.obfuscationSuspect = obfuscationSuspect;

    // Operator info presence — check FULL body text (not truncated) AND link text/href
    const fullText = bodyTextFull.toLowerCase();
    const linkTexts = links.map(a => (a.textContent || '').toLowerCase() + ' ' + (a.getAttribute('href') || '').toLowerCase()).join(' ');
    const allText = fullText + ' ' + linkTexts;
    // Organization info: corporate, law firm, medical, NPO, etc.
    const ORG_INFO_RE = /会社概要|企業情報|企業概要|運営会社|運営者情報|運営情報|事業者[名情]|販売[者業]|屋号|事務所[概名情]|代表弁護士|弁護士登録番号|所属弁護士会|代表取締役|代表者|代表理事|理事長|院長|施設長|クリニック概要|医院概要|病院概要|法人[概情]|団体概要|組織概要|about\s*us|company\s*info|corporate/i;
    result.hasCompanyInfo = ORG_INFO_RE.test(allText);
    // Contact: phone, email, address, access
    result.hasContact = /お問い合わせ|連絡先|contact|電話番号|tel[：:]|mail[：:]|所在地|住所|アクセス[マ情]|fax[：:]/i.test(allText);
    result.hasPrivacyPolicy = /プライバシー|privacy|個人情報保護/i.test(allText);
    result.hasCommerceLaw = /特定商取引|特商法|返品[特交]|返金[ポ規]/i.test(allText);
    // Distinguish: found as link (to another page) vs found in page content
    result.companyInfoInContent = ORG_INFO_RE.test(fullText);
    result.commerceLawInContent = /特定商取引|特商法/i.test(fullText);

    // Hidden elements
    const allEls = doc.querySelectorAll('*');
    let hiddenFormFields = 0;
    allEls.forEach(el => {
      const style = el.getAttribute('style') || '';
      if (/display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0/.test(style)) {
        if (el.tagName === 'INPUT' || el.tagName === 'FORM') hiddenFormFields++;
      }
    });
    result.hiddenFormFields = hiddenFormFields;

    return result;
  }
};

// ============================================================
// Gemini API Client
// ============================================================
const GeminiClient = {
  async analyze(config, urlStr, urlAnalysis, htmlContent, headers) {
    const workerUrl = (config.workerUrl || DEFAULT_WORKER_URL).replace(/\/+$/, '');
    const apiKey = config.apiKey;

    const sensitivity = loadSensitivity();
    const prompt = this._buildPrompt(urlStr, urlAnalysis, htmlContent, headers, sensitivity);
    const schema = this._responseSchema();

    const body = {
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: {
        responseMimeType: 'application/json',
        responseSchema: schema,
        temperature: 0.1
      }
    };

    const resp = await fetch(`${workerUrl}/models/gemini-2.5-flash:generateContent`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-Key': apiKey },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(60000)
    });

    if (!resp.ok) {
      const errText = await resp.text();
      if (resp.status === 429) {
        throw new Error('Gemini APIの利用上限に達しました。しばらく待ってから再度お試しください。');
      }
      throw new Error(`Gemini API error ${resp.status}: ${errText.slice(0, 200)}`);
    }

    const data = await resp.json();
    const text = data.candidates?.[0]?.content?.parts?.[0]?.text;
    if (!text) throw new Error('Gemini returned empty response');
    let parsed;
    try { parsed = JSON.parse(text); } catch { throw new Error('AI応答のJSON解析に失敗しました'); }
    if (!parsed.scores || typeof parsed.scores.domain_trust !== 'number') {
      throw new Error('AI応答に必須フィールドがありません');
    }
    return parsed;
  },

  _buildPrompt(urlStr, urlAnalysis, htmlContent, headers, sensitivity) {
    const today = new Date().toISOString().slice(0, 10);

    let sensitivityInstruction = '';
    if (sensitivity === 'high') {
      sensitivityInstruction = '\n## 感度設定: 高感度モード\n疑わしい場合は積極的に低スコアを付けてください。グレーゾーンのサイトは安全側ではなく危険側に寄せて判定してください。\n';
    } else if (sensitivity === 'low') {
      sensitivityInstruction = '\n## 感度設定: 低感度モード\n明確な根拠がある場合のみ低スコアを付けてください。グレーゾーンのサイトは危険側ではなく安全側に寄せて判定してください。\n';
    }

    return `あなたはサイバーセキュリティ専門家です。以下のウェブサイト情報を分析し、詐欺・危険サイトかどうかを判定してください。
本日の日付: ${today}

## 回答ルール（最重要・厳守）
0. **必ず日本語で回答してください。** findings/detected_categories/summaryの全フィールドを日本語で記述すること。
1. findingsのquoteには、サイト本文からの「そのまま引用」のみ記載。存在しない文言を捏造しない。
2. 引用できる原文がない場合はquoteを空文字にする。
3. detected_categoriesのevidenceも、サイト内の具体的表現を根拠として示す。
4. 正当なサイトには高スコアを付ける。疑わしい点がなければ安全と判定する。
5. 推測や可能性だけで低スコアを付けない。具体的根拠がある場合のみ減点する。ただし根拠が明確な場合は躊躇なく低スコアを付けること。
6. 複数カテゴリの部分一致だけで危険と判定しない。文脈と全体像を重視する。ただし、19カテゴリの手口パターンに明確に合致する場合は、scam_patternを20以下にすること。
8. 誤検知防止ガイドは正当なサービスを守るためのもの。詐欺サイトが正当なサービスの特徴を装っている場合（例: 偽の登録番号、コピペされた免責文）は保護対象外。
7. この分析は「現時点でのこのページの内容」のみが対象。過去の行政処分歴や企業の評判は判断材料にしない。
${sensitivityInstruction}
## 対象URL
${urlStr}

## クライアント側URL分析結果
- ドメイン信頼スコア: ${urlAnalysis.domain_trust}/100
- 技術安全スコア: ${urlAnalysis.tech_safety}/100
- 検出された問題: ${urlAnalysis.issues.length > 0 ? urlAnalysis.issues.map(i => i.title).join(', ') : 'なし'}

## HTTPレスポンスヘッダー
${headers ? Object.entries(headers).map(([k,v]) => `${k}: ${v}`).join('\n') : '取得不可'}

## サイトコンテンツ
タイトル: ${htmlContent?.title || '不明'}
見出し: ${htmlContent?.headings?.join(' / ') || 'なし'}
本文テキスト:
${htmlContent?.bodyText || '取得不可'}

外部リンク数: ${htmlContent?.externalLinkCount || 0}
外部ドメイン: ${htmlContent?.externalDomains?.join(', ') || 'なし'}
フォーム: ${htmlContent?.forms?.length || 0}個${htmlContent?.forms?.some(f => f.hasPassword) ? '（パスワード入力あり）' : ''}${htmlContent?.forms?.some(f => f.hasCard) ? '（クレジットカード入力あり）' : ''}
インラインスクリプト: ${htmlContent?.inlineScriptChars || 0}文字
難読化の疑い: ${htmlContent?.obfuscationSuspect ? 'あり' : 'なし'}
隠しフォーム要素: ${htmlContent?.hiddenFormFields || 0}個
会社概要: ${htmlContent?.companyInfoInContent ? 'ページ内に記載あり' : htmlContent?.hasCompanyInfo ? 'リンクあり（別ページに存在）' : 'なし'}
連絡先: ${htmlContent?.hasContact ? 'あり' : 'なし'}
プライバシーポリシー: ${htmlContent?.hasPrivacyPolicy ? 'あり' : 'なし'}
特定商取引法表記: ${htmlContent?.commerceLawInContent ? 'ページ内に記載あり' : htmlContent?.hasCommerceLaw ? 'リンクあり（別ページに存在）' : 'なし'}

## 検出すべき詐欺・違法サイトカテゴリ（19種）と実際の手口パターン

### 1. 闇バイト（犯罪実行者募集）
警察庁統計: 2024年首都圏連続強盗19件・46人逮捕。Telegram/Signal経由で指示。
**検出フレーズ:**
- 「高額報酬」「高額バイト」「即日払い」「即日即金」「ホワイト案件」
- 「楽に稼げる」「リスクのない」「～するだけ」「日給5万円から」
- 「人から物を受け取るだけ」「現金を引き出すだけの高額バイト」
- 「荷物を受け取るだけ」「運びの仕事」「引っ越し 即日払い10万円」
- 「報酬35万円 資金調達」「深夜に人を運んでください」
**隠語:** UD/受け出し、U/受け子、D/出し子、T/タタキ/叩き、打ち子、荷受け、運び、飛ばし
**特徴:** SNS(X/Instagram)→Telegram/Signalへ誘導、身分証提出要求→脅迫で逃げられなくなる

### 2. 投資詐欺（SNS型）
2024年被害: 10,237件・1,271.9億円（前年比179.4%増）。金融庁相談15,054件中83.2%が実被害。
**検出フレーズ:**
- 「必ず儲かる」「元本保証」「確実に利益が出る」「上場確実」
- 「あなただけにご紹介」「限定○名」「今だけ特別」「無料の投資セミナー」
- 「著名人○○が推薦」（有名人なりすまし広告）
- 「先生のおかげで利益が出ました」「先生の指示どおりにやって成功しました」（サクラ投稿）
- 「出金には手数料が必要です」「税金を支払わないと出金できません」（出金拒否）
**手口:** Facebook/Instagram偽広告→LINEグループ誘導→「先生」「アシスタント」が指導→サクラが利益報告→少額出金で信用→高額投入→連絡断絶or出金手数料要求
**有名人偽装事例:** 森永卓郎(偽広告3,035件)、堀江貴文、前澤友作、池上彰
**関連法令:** 金融商品取引法で「断定的判断の提供」禁止。金融庁無登録業者リスト公表中。登録番号詐称事例あり。

### 3. フィッシング
2024年通報: 年間171.8万件（過去最多）。12月単月23.2万件。74.9%が送信元偽装。
**なりすまし上位10ブランド:** Amazon、えきねっと、PayPay、佐川急便、国税庁、Mastercard、Apple、三井住友カード、JA Bank、JCB（上位10で73.7%）
**検出フレーズ（SMS/メール）:**
- 「不在のため持ち帰りました」「お荷物投函のお知らせ」（宅配偽装）
- 「お客様の口座が不正アクセスされています」「セキュリティの再設定が必要です」
- 「カードの利用を一時停止しました」「不正利用の可能性がある」
- 「暗証番号の有効期限が切れる」「○日間ログインされていません」
- 「至急対応が必要です」「24時間以内に」「アカウントが停止されます」
- 「【えきねっと】お支払い情報のご確認と更新のお願い」
- 「Amazonアカウントの情報を更新する必要があります」
- 「未納の税金があります」「【国税庁】重要なお知らせ」
- 「電力供給が停止される可能性があります」（東京電力偽装）

### 4. 偽通販
JC3通報: 2023年47,278件（前年比+64%）。国民生活センター: インターネット通販関連年間27万件超。
**検出パターン:**
- 激安価格（正規の80-95%引き）、先払いのみ（銀行振込/プリペイドカード）
- 振込先が個人名義口座（外国人名義含む）
- 不自然な日本語（機械翻訳調）、中国語使用の見慣れない漢字
- 実在しない会社情報、特商法表記の欠如、連絡先なし
- 正規ECサイトのデザイン・商品写真を無断コピー
- 不審TLD: .top/.xyz/.site/.online/.fun/.icu
**結末:** 商品未着・偽物送付・空箱送付。代金騙し取り後に連絡不能。

### 5. 健康詐欺・医療広告違反
**薬機法違反（逮捕事例）:**
- 「がん細胞が自滅する」→ シンゲンメディカル社逮捕(2019年)
- 「ズタボロになった肝臓が半年で復活」→ ステラ漢方社逮捕(2020年)
- 「血液をきれいにする」「糖尿病が治る」→ 医療機器販売会社逮捕(2025年)
- 「アトピーが治る」「がんに効く」→ 書類送検。化粧品「シワがなくなる」「シミが消える」→ 効能範囲逸脱
- 無承認医薬品: ダイエットジェリー(シブトラミン検出・6名健康被害)、美白クリーム(皮膚障害)
**景品表示法違反（措置命令事例）:**
- 「食事制限や運動なしで短期間で痩身効果」→ シボローカ/フラボス措置命令(2024年3月)
- 「短期間で薄毛改善」「白髪→黒髪」→ MIHORE措置命令(2024年10月)
- 「摂取するだけで腹部の脂肪が落ちる」→ メラット措置命令(2023年)
- 「シミが99.9%消える」→ HappyLifeBio社措置命令(2024年)
**検出キーワード:** 「飲むだけで」「塗るだけで」「楽ヤセ」「不治の病が完治」「奇跡の○○」「食事制限不要」「驚きの効果」
**医療広告ガイドライン違反（厚労省 2023年度: 1,098サイト/6,328件）:**
- 美容362サイト、歯科374サイト、がん68サイト
- 「必ず治る」「100%安全」「副作用なし」「痛みゼロ」→ 誇大広告
- ビフォーアフター写真でリスク・副作用記載不十分、未承認医薬品を用いる自由診療の情報提供不足
**施術所広告違反（あはき法・柔整法）:** 「交通事故専門」「肩こり治療」→行政指導対象。無資格マッサージ→エーワン社逮捕。

### 6. 被害回復詐欺（二次被害詐欺）
特殊詐欺全体: 2024年21,043件・717.6億円（前年比+58.6%）。被害者リスト流通で二次被害が発生。
**型A: 古典的被害回復詐欺（劇場型・偽公的機関型）**
- 「詐欺被害を取り戻す」「返金保証」「被害者救済」「被害を回復してあげます」
- 「△△社の株を買ってくれたら、あとで高く買い取ります」（劇場型二次被害）
- 「以前の投資の損を取り戻せる」「振り込んだお金を取り戻す手続きがある」
- 偽の検察庁通知「被害回復給付金支給」で手数料請求。振り込め詐欺救済法を悪用した手数料名目の金銭要求。
**型B: 調査会社・デジタルフォレンジック型（近年急増）**
詐欺被害者をターゲットに「調査会社」「デジタルフォレンジック」を名乗り、被害金回収の調査費用を請求する手口。実際には仮想通貨の回収はほぼ不可能。
**重要な事実: 暗号資産（仮想通貨）は一度送金すると、海外ウォレットへ移動された資金を民間企業が回収することは技術的にほぼ不可能。「ブロックチェーン解析で追跡・回収」は非現実的な主張。**
**型Bの検出フレーズ:**
- 「騙し取られたお金を追跡」「被害金回収」「被害金の回収」「返金の可能性を調査」
- 「ブロックチェーン解析」「デジタルフォレンジック」「資金の流れを追跡」「資金移動の経路特定」
- 「仮想通貨の追跡」「ウォレットアドレスの追跡」「暗号資産の回収」
- 「警察や弁護士では難しい」「弁護士に断られた」「警察が動いてくれない」→「当社なら」
- 「証拠収集のプロ」「専門の調査会社にお任せ」「調査会社だからできる」
- 「無料一次調査」「無料で調査」「被害金回収の可能性を無料で」
- 「手遅れになる前に」「早めの対応が重要」「今なら回収できる可能性」
**型Bの危険シグナル:**
- 仮想通貨詐欺の「返金事例」「回収事例」を掲載（実際には回収不可能なケースがほとんど）
- 探偵業届出番号の不記載（調査業を営むには公安委員会届出が必要）
- 「弁護士や警察ではできない」と不安を煽り、自社サービスに誘導
- 被害者の恐怖心・焦りを煽る緊急性表現の多用
- 投資詐欺の手口を詳しく解説→「心当たりがあれば今すぐ相談」の構成
- 調査費用が被害額の数%（高額被害だと調査費用自体が数十万〜数百万円）
**正当な被害回復サービスとの区別（重要）:**
振り込め詐欺救済法（犯罪利用預金口座等に係る資金による被害回復分配金の支払等に関する法律）に基づき、国内銀行口座への振込詐欺では口座凍結→被害金分配による回収が法的に可能。以下は正当なサービス:
- 弁護士が振り込め詐欺救済法に基づく口座凍結・分配金申請を支援
- 弁護士が発信者情報開示請求・損害賠償請求を代理
- 警察への被害届提出を支援する行政書士・弁護士
→ 弁護士（日本弁護士連合会登録番号あり）が法的手続きの範囲で被害回復を行うサイトは正当。減点しない。
**詐欺と判定すべきケース:**
- 弁護士資格なしで「被害金回収」を主要サービスとして謳う調査会社
- 仮想通貨・暗号資産の「回収」「追跡して取り戻す」を謳うサービス（技術的にほぼ不可能）
- 「弁護士や警察では無理→当社なら」と法的専門家を否定して自社に誘導
- 探偵業届出番号の記載なく調査業務を謳う
→ これらが該当する場合、scam_patternを20以下、claim_credibilityを30以下とすること。

### 7. サポート詐欺
IPA 2024年Q1相談: 1,385件（偽ウイルス警告のみ）。2023年以降ネットバンキング乗っ取り事例あり。
**検出フレーズ（偽警告画面）:**
- 「Windows Defender セキュリティセンター」（偽装）
- 「トロイの木馬スパイウェアに感染したPC」
- 「エラーコード: #0x898778」「エラーコード #0x2680d3」
- 「この PC へのアクセスはブロックされました」
- 「このウィンドウを閉じると、個人情報が危険にさらされ Windows 登録が停止されます」
- 「今すぐサポートセンターに電話してください」
- 電話番号050-xxxx-xxxx or 0101-xxx-xxxx（国際電話）
**手口:** ブラウザ全画面偽警告+音声再生→電話させる→プリペイドカード購入指示 or AnyDesk/TeamViewer遠隔操作→ネットバンキング不正送金
**偽装ブランド:** Microsoft、Windows Defender、McAfee、Norton、Apple

### 8. ロマンス詐欺（豚殺し/Pig Butchering）
2024年1-9月被害: 271億円（前年2.4倍）。平均被害額1,242.7万円。
**検出フレーズ:**
- 「一緒に投資しませんか」「2人の将来のために」「一緒に稼ごう」
- 「投資でお金を増やそう」「あなたのことが好きです」
- 「会いたいから旅費を送って」「病気の家族の治療費が必要」
- 「荷物を送るから手数料を払って」
**手口:** マッチングアプリ/SNS DM→LINE/WhatsApp/Telegramで親密化→偽取引プラットフォームへ誘導→偽の利益表示→出金時に手数料/税金要求
**大型事例:** 女性社長がSNSで知り合った外国人に約80回・4.6億円を送金

### 9. 違法オンラインカジノ
2024年賭博事犯検挙279人（前年比2.6倍・過去最多）。利用者推定330万人、掛金1兆円超。日本国内からの利用は賭博罪。
**検出フレーズ:**
- 「オンラインカジノ」「ライブカジノ」「オンラインスロット」「ネットポーカー」
- 「入金ボーナス100%」「初回入金ボーナス」「フリースピン」「キャッシュバック」
- 「出金条件」「賭け条件」「ベット額」「VIPプログラム」
- 「必勝法」「攻略ツール」「カジノ攻略」「勝てるスロット」
- 「ライセンス取得済み」「マルタライセンス」「キュラソーライセンス」（海外ライセンスで合法を装う）
**サイト構造の特徴:** 派手なUI、ゲーム一覧グリッド、入金/出金ボタン、ライブチャットウィジェット、年齢確認ダイアログ、多通貨対応（JPY/BTC）
**注意:** 海外で合法でも日本からの利用は犯罪。「合法」「安全」と謳う日本語サイトは全て違法勧誘。

### 10. 偽造品・ブランドコピー品販売
2024年税関差止33,019件（過去最多）。商標法違反：10年以下の懲役/1,000万円以下の罰金。
**検出フレーズ:**
- 「スーパーコピー」「N級品」「S級品」「レプリカ」「コピー品」
- 「本物と見分けがつかない」「正規品と同品質」「1:1再現」
- 「激安ブランド」「アウトレット特価」「工場直販」「海外直送」
- 「ルイヴィトン 激安」「ロレックス コピー」等のブランド名+激安/コピー
**サイト構造の特徴:** 正規価格から80-95%引きの異常な低価格、大量のブランド名羅列、銀行振込のみ（クレカ不可と異なる表示）、不自然な日本語、whois海外登録
**消費者庁事例:** ブランド品公式サイトを装った偽サイトが年間数百件確認。代金を騙し取るか、粗悪品・偽物・空箱を送付。

### 11. 架空請求・ワンクリック詐欺
手口は陳腐化傾向だがIPA相談は四半期15件程度で継続中。
**検出フレーズ（偽請求画面）:**
- 「ご登録ありがとうございます」「有料会員登録が完了しました」
- 「料金が発生しました」「利用料金○○万円」「延滞金が加算されます」
- 「○日以内にお支払いください」「期限内にお振込みください」
- 「法的措置を取らせていただきます」「少額訴訟の手続きに移行」
- 「お客様のIPアドレス」「個体識別番号」「端末情報を取得しました」（脅迫要素）
- 「退会希望の方はこちら」（連絡させてさらに騙す）
**サイト構造の特徴:** IPアドレス/ユーザーエージェント表示、カウントダウンタイマー、振込先銀行口座情報の表示、閉じるボタンの無効化

### 12. 副業・タスク詐欺
消費者庁への相談1,615件、送金額合計10億円超（2024年）。平均被害額約106万円。
**検出フレーズ:**
- 「スマホだけで月○万円」「1日5分で稼げる」「すき間時間で副収入」
- 「いいねを押すだけ」「スクショを撮るだけ」「動画を見るだけ」「タップするだけ」
- 「未経験OK」「スキル不要」「誰でもできる」「主婦でも稼げる」
- 「初期費用0円」「無料で始められる」→後から高額マニュアル/ツール購入を要求
- 「LINE登録で詳細」「公式LINE追加」→LINEグループで洗脳
**手口:** SNS広告/DM→LINE登録→少額タスク（いいね等）で少額報酬支払い→「上位タスク」として高額送金を要求→出金不可
**特徴:** Telegramグループへの誘導、送金先が個人名義の口座

### 13. なりすまし広告詐欺（フェイク広告）
2024年上半期被害額506億円。Meta社提訴（被害者30人、請求3億円超）。
**検出フレーズ:**
- 「○○氏も推薦」「○○が実践する投資法」（著名人名の無断使用）
- 偽ニュース記事風LP：「【速報】○○氏が語る驚きの投資法」「NHKニュースで話題」「日経新聞掲載」
- 「衝撃の事実」「まだ知らないの？」「○○だけが知っている」
- 「期間限定 無料公開中」「今だけ特別に」「先着○名」
**サイト構造の特徴:** ニュース記事風デザイン、偽のメディアロゴ、著名人の写真大量使用、Facebook/Instagram広告からの遷移、最終的にLINE誘導
**偽装対象:** 森永卓郎、堀江貴文、前澤友作、池上彰等。NHK・日経新聞等のメディアロゴ偽装。
**AIディープフェイク(JFC 2024年検証330件):** 堀江貴文AI音声→被害2.2億円、前澤友作→Meta提訴、岸田首相偽動画。偽ニュース:「柳井正拘束」「高市議員提訴」→JFC虚偽判定。災害偽情報: 能登震災「人工地震」10万件・偽救助要請2.1万件・偽寄付募集350件。

### 14. 仮想通貨・暗号資産詐欺
SNS型投資詐欺(暗号資産含む): 2024年10,237件・1,271.9億円。金融庁2024年: KuCoin/Bybit/MEXC/Bitget/Bitcastle5社に無登録警告。
**大型事件:** ジュビリーエース650億円(2021年7人逮捕)、テキシアジャパン460億円(1.3万人被害)、OZプロジェクト65億円(「4カ月で2.5倍」)
**検出フレーズ:**
- 「年利○○%保証」「月利○%確定」「必ず値上がりする」「元本保証のステーキング」
- 「AI自動売買」「最新AIが自動で運用」「完全自動で利益」
- 「ICO特別先行販売」「プレセール限定」「上場確定コイン」
- 「出金手数料○万円」「マイニング報酬」「エアドロップ」
- 「ウォレット接続」（偽DeFiサイトでのウォレット資金窃取）
**サイト構造の特徴:** 偽の取引チャート/利益表示、リアルタイム風の取引履歴、金融庁登録番号の偽造、著名取引所のUIコピー
**注意:** 金融庁の暗号資産交換業者登録一覧にない業者は全て無登録違法業者。

### 15. 情報商材詐欺
国民生活センター相談: 2017年6,593件(ピーク)。連鎖販売取引相談年間約1万件。
**消費者庁事業者名公表:** 株式会社サポート(副業マニュアル2022年)、株式会社協栄商事/フィールド(遠隔操作アプリ悪用2024年)、株式会社和(「月50万が当たり前」2024年)
**マルチ商法:** 日本アムウェイ6カ月業務停止命令(2022年10月、マッチングアプリ/SNS経由勧誘)
**検出フレーズ:**
- 「稼げるノウハウ」「○○するだけで月収100万円の方法」
- 「限定公開」「残り○名」「期間限定」「本日23:59まで」
- 「通常価格○○万円→今だけ○万円」（二重価格）
- 「成功者の声」「実践者○○人が成果を出した」（サクラの体験談）
- 「返金保証付き」（条件が厳しく実質返金不可）
- 「無料セミナー」「無料ウェビナー」→高額バックエンド商材への誘導
**サイト構造の特徴:** 縦長LP、カウントダウンタイマー、スクロール追従CTAボタン、煽り色（赤/黄）の多用、偽の「残り○名」表示、札束/高級車の画像
**手口:** 無料メルマガ/LINE→無料セミナー→30万〜200万円の「塾」「コンサル」「ツール」購入を迫る

### 16. 闇金・違法貸金業（ソフト闇金/給料ファクタリング含む）
警察庁: 2023年検挙671事件。被害額55億円超(2022年)。最高裁「給料ファクタリングは貸金業法適用の貸付」(2023年)。
**逮捕事例:** クレカ現金化85億円貸付(BPMH社13人逮捕2025年)、先払い買取「買取キング」2億3,800万円(2024年)、「まるかい」延べ1.2万人(2024年)、後払い現金化「ギフリー」(2023年)
**手口の進化:** 給料ファクタリング→後払い現金化→先払い買取→クレカ現金化と形態を変え復活
**検出フレーズ:**
- 「ブラックOK」「ブラックでも借りれる」「審査なし」「審査不要」
- 「即日融資」「即日振込」「来店不要」「誰でも借りれる」
- 「ソフト闇金」「優良ソフト闇金」（自称する違法業者が多数存在）
- 「給料買取」「給料ファクタリング」「後払い現金化」（実質高利貸し）
- 「090-xxxx-xxxx」「080-xxxx-xxxx」（携帯番号のみ＝090金融）
**サイト構造の特徴:** 携帯電話番号のみの連絡先、貸金業登録番号の記載なし or 偽造、「お申し込みはLINEで」
**注意:** 正規の貸金業者は必ず財務局または都道府県知事の登録番号を持つ。登録番号は金融庁のデータベースで確認可能。

### 17. 著作権侵害・海賊版サイト
年間被害額3,300〜4,300億円超。漫画だけで年間1兆円超との推計。月間約6億アクセス。
**検出フレーズ:**
- 「全巻無料」「全話無料」「最新話 無料」「先読み 無料」
- 「無料で読める」「無料視聴」「無料ダウンロード」
- 「manga raw」「manga free」「zip ダウンロード」「torrent」
- 「○○ 全巻 rar」「○○ raw」（作品名+raw/zip/rar）
- 「映画 無料 フル」「アニメ 無料 全話」「ドラマ 見逃し 無料」
**サイト構造の特徴:** 大量のコンテンツリスト（漫画/アニメ/映画）、aggressive広告（ポップアップ/リダイレクト多数）、Cloudflare等のCDN使用、海外ドメイン、広告ブロッカー検出
**注意:** 2021年著作権法改正により海賊版と知りながらのダウンロードも違法化。漫画村の賠償額17.3億円（2024年判決）。

### 18. 還付金詐欺・偽行政サイト
2024年還付金詐欺 認知件数4,070件・被害額63.7億円。偽マイナポータルサイトも出現。
**検出フレーズ:**
- 「還付金があります」「払い戻しのお知らせ」「医療費の還付手続き」
- 「保険料の過払い」「年金の未払い分」「税金の還付」
- 「手続き期限が迫っています」「○月○日までに手続きしないと無効」
- 「マイナポータル」「e-Tax」「ねんきんネット」（行政サイト偽装）
- 「マイナンバーを入力してください」「本人確認のため暗証番号を入力」
**サイト構造の特徴:** 行政機関のロゴ・デザインを模倣、.go.jpでないドメイン、マイナンバー/暗証番号の入力フォーム
**注意:** 行政機関が還付金の手続きでATM操作やネットバンキングを指示することは絶対にない。公式サイトのドメインは必ず.go.jp。

### 19. 霊感商法・スピリチュアル詐欺・疑似科学
開運商法PIO-NET相談: 年間1,200〜1,500件。占いサイト相談: 年間2,000件超(8割女性)。2022年消費者契約法改正で霊感商法取消期間5→10年。不当寄附勧誘防止法2023年施行。
**逮捕事例:** 「神世界」ヒーリングサロン5,000万円詐取(2011年)、統一教会関連10件40名逮捕
**占いサイト詐欺事例:** 120万円(守護霊で引き止め)、55万円(宝くじ高額当選を保証)、400万円。1通1,000〜1,500円のポイント課金。
**疑似科学商品:** 水素水(国民生活センター2,260件・3社+生成器4社措置命令)、マイナスイオン空気清浄機2社措置命令(2023年)、ゲルマニウムブレスレット(含有ゼロ・健康効果根拠なし)、EM菌(科学的検証データなし)
**検出キーワード（霊感系）:**
- 「前世の因縁」「先祖の祟り」「悪霊」「水子の霊」「霊障」「除霊」「浄霊」「お祓い」
- 「開運印鑑」「パワーストーン」「霊感鑑定」「霊視」「祈祷料」「供養料」
**検出キーワード（占い詐欺）:**
- 「無料鑑定」「あなたは特別」「金運」「守護霊」「宝くじ当選」「あと一通で完了」
**検出キーワード（疑似科学）:**
- 「水素水」「活性水素」「マイナスイオン」「ゲルマニウム」「EM菌」「波動水」
- 「活性酸素を除去」「デトックス」「好転反応」「クラスター水」「遠赤外線効果」
**共通の危険シグナル:** 「科学では説明できない」「医者も驚く」「奇跡の」「好転反応（一時的な悪化は効果の証拠）」

## 広告・表示規制違反パターン（実際の行政処分事例）
以下は主に正規企業にも適用される景品表示法・特商法の違反パターンです。上記19カテゴリと異なり、一見正当なサイトでも該当し得ます。

**虚偽No.1表示(2024年14社集中取締り):** 「顧客満足度No.1」「売上No.1」「医師の○%が推奨」→ 実態はイメージ調査のみ。検出: 「No.1」「第1位」「満足度98%」+ 根拠調査の記載なし。
**効果なし商品(合理的根拠なし):** 「糖質カット」炊飯器8社(水分希釈)、「空間除菌」4社、「クレベリン」10社 → 全て措置命令。検出: 「除菌」「糖質カット」+ 根拠なし。
**二重価格・有利誤認:** 「通常価格○○円→今だけ△△円」(販売実績なし)。メルセデス・ベンツ12.3億円課徴金(2024年)。
**ステルスマーケティング(2023年10月施行・6件処分):** 祐真会(初処分)・RIZAP・大正製薬・ロート製薬 → 口コミ・体験談にPR/広告表記なし。検出: レビューに「PR」「広告」「提供」表記がない。
**打消し表示:** 強調表示と矛盾する条件文が極小フォント(8pt未満)。例:「いつでもどこでも」+小文字「エリアにより不可」。
**定期購入ダークパターン(年間約9万件相談):** 「初回550円」→2回目3.9万円自動発送、「いつでも解約」→クーポンで定期コース変更、解約条件の深い位置配置。検出: 「初回限定」「お試し」「97%OFF」+ 解約条件不明瞭。
**グリーンウォッシュ:** 「生分解性」プラ製品10社措置命令(2022年)。検出: 根拠なき「エコ」「地球にやさしい」「カーボンニュートラル」。

## 誤検知防止ガイド（重要）
以下に該当するサイトは、上記カテゴリのキーワードに部分一致しても安全性を高く評価すること。

**運営者透明性の評価ルール（重要）:**
- 特定商取引法に基づく表記は「通信販売」を行う事業者にのみ義務付けられている。病院・学校・NPO・メディア・企業コーポレートサイト・行政機関等、物品販売やサービスの通信販売を行っていないサイトには不要であり、表記がなくても減点しないこと。
- 会社概要・連絡先・プライバシーポリシーが「リンクあり（別ページに存在）」の場合、別ページに情報が存在する正当な構成であるため、「なし」と同等に減点しないこと。トップページやサービスページに直接記載されていなくても、フッターリンク等から辿れるなら十分。
- 会社概要・特商法表記がいずれもないサイトでも、商品販売を行っていない情報提供サイト・ブログ・メディアであれば問題ない。
- 運営者情報は「会社概要」以外にも多様な形式で記載される。法律事務所なら「事務所概要」「代表弁護士」「弁護士登録番号」「所属弁護士会」、医療機関なら「院長」「診療科目」「医療法人名」、NPOなら「団体概要」「代表理事」等。本文中にこれらの情報が含まれていれば、見出しの有無にかかわらず運営者情報ありと評価すること。

**運営者情報の偽装パターンに注意:**
以下は運営者情報があるように見せかける詐欺的手法。これらに該当する場合は運営者透明性を高く評価しないこと:
- 「弁護士監修」「専門家監修」「医師推奨」→ 監修と運営は別物。実際の運営者・責任者が不明なら不透明。
- 「○○協会認定」「○○機構公認」→ 実在しない団体名や自作団体の可能性。公的な登録番号（弁護士登録番号、金融商品取引業者登録番号、探偵業届出番号等）と異なり、検証不能な肩書きは信頼の根拠にならない。
- 住所がバーチャルオフィスやレンタルポスト（例: 「○○ビル△号室」だけで、検索すると格安レンタルオフィス）で、かつ電話番号がIP電話（050-）のみ → 実体がない可能性。
- 「代表 ○○」とフルネームがあるが、検索しても存在確認できない人物名。
- 登録番号の体系が正しくない（例: 弁護士登録番号は5-6桁の数字、金商登録は「関東財務局長(金商)第○○号」形式）。

**正当な金融サービスの特徴:**
- 金融庁の登録番号（関東財務局長(金商)第○○号等）が記載され、番号体系が正しい
- 金融商品取引法に基づくリスク説明・手数料開示がある
- 「元本割れの可能性があります」等のリスク注意文がある
→ 「投資」「利益」等のキーワードがあっても、これらが揃っていれば正当な金融サービス。

**正当な健康食品・サプリ販売の特徴:**
- 「栄養補助食品」「個人の感想です」「効果を保証するものではありません」等の免責表記
- 特定商取引法に基づく表記が完備（事業者名・住所・電話番号・返品条件）
- 機能性表示食品の届出番号や特定保健用食品の許可番号
→ 「健康」「サプリ」等のキーワードだけで減点しない。

**正当な占い・スピリチュアルサービスの特徴:**
- 料金体系が明確に表示されている
- 特商法表記が完備、解約方法が明示
- 「娯楽目的」等の位置づけが適切
→ 「占い」「鑑定」等のキーワードだけで減点しない。正当な有料サービスと詐欺的サイトの違いは、料金の透明性・解約容易性・煽り表現の有無。

**正当なECサイトの特徴:**
- 特商法表記完備、クレジットカード決済対応、返品ポリシー明示
- 会社情報が実在確認可能、電話番号あり
→ 「セール」「割引」等のキーワードだけで偽通販と判定しない。

**グレーゾーンの扱い:**
正当なサービスと詐欺の境界にあるサイト（例: 高額だが違法ではない情報商材、誇大だが薬機法ギリギリの広告）は、具体的にどの点が懸念されるかをfindingsで説明し、最終判断はユーザーに委ねる。中間スコア（40-70）を使う。

**重要: 明白な詐欺サイトへの対応:**
上記の誤検知防止ガイドは、正当なサービスを不当に低評価しないためのもの。以下の特徴が複数該当するサイトは詐欺の可能性が高く、積極的に低スコアを付けること:
- 19カテゴリの手口パターンに明確に合致する表現・構成がある
- 煽り表現（「今すぐ」「残りわずか」「本日限り」）が複数箇所にある
- 連絡先・運営者情報が欠如し、かつ金銭の支払いや個人情報入力を求めている
- 非現実的な利益・効果を断定的に約束している（「確実」「保証」「絶対」）
- 不審なドメイン構造（ランダム文字列、ブランド偽装、不審TLD）と内容の危険性が重なる
これらが該当する場合、overall_riskをhigh以上とし、対応するスコアを30以下にすること。

**注意: 詐欺サイトは正当に見える外観を持つことがある:**
会社名・住所・電話番号・特商法リンクがあっても、サービス内容自体が詐欺的なら高評価にしない。特に被害回復詐欺（Cat6型B）は、プロフェッショナルな外観・会社概要・調査事例を揃えて信頼感を演出するが、核心のサービス（仮想通貨の回収等）が技術的に不可能。運営者情報の有無よりサービス内容の実現可能性を重視すること。

## 評価基準
各次元を0-100で評価（100が最も安全）:
- domain_trust: ドメイン信頼性（URL構造、TLD、ブランド偽装、SSL）
- content_safety: コンテンツ安全性（不審キーワード、煽り表現、緊急性）
- operator_transparency: 運営者透明性（特商法表記、会社概要、連絡先）
- claim_credibility: 主張の信頼性（誇大広告、非現実的保証、法令違反表現）
- scam_pattern: 詐欺パターン非合致度（既知パターンとの非類似度。高いほど安全）
- tech_safety: 技術的安全性（SSL、難読化、隠しフォーム）

`;
  },

  _responseSchema() {
    return {
      type: 'object',
      properties: {
        scores: {
          type: 'object',
          properties: {
            domain_trust: { type: 'number' },
            content_safety: { type: 'number' },
            operator_transparency: { type: 'number' },
            claim_credibility: { type: 'number' },
            scam_pattern: { type: 'number' },
            tech_safety: { type: 'number' }
          },
          required: ['domain_trust','content_safety','operator_transparency','claim_credibility','scam_pattern','tech_safety']
        },
        overall_risk: { type: 'string', enum: ['safe','low','medium','high','critical'] },
        detected_categories: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              category: { type: 'string' },
              confidence: { type: 'string', enum: ['high','medium','low'] },
              evidence: { type: 'string' }
            },
            required: ['category','confidence','evidence']
          }
        },
        findings: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              dimension: { type: 'string' },
              severity: { type: 'string', enum: ['critical','high','medium','low','info'] },
              title: { type: 'string' },
              description: { type: 'string' },
              quote: { type: 'string' }
            },
            required: ['dimension','severity','title','description']
          }
        },
        summary: { type: 'string' }
      },
      required: ['scores','overall_risk','detected_categories','findings','summary']
    };
  }
};

// ============================================================
// Score Integrator
// ============================================================
const ScoreIntegrator = {
  DIMENSIONS: [
    { key: 'domain_trust', label: 'ドメイン信頼性', shortLabel: 'ドメイン' },
    { key: 'content_safety', label: 'コンテンツ安全性', shortLabel: 'コンテンツ' },
    { key: 'operator_transparency', label: '運営者透明性', shortLabel: '運営者' },
    { key: 'claim_credibility', label: '主張の信頼性', shortLabel: '主張' },
    { key: 'scam_pattern', label: '詐欺パターン非合致', shortLabel: '詐欺パターン' },
    { key: 'tech_safety', label: '技術的安全性', shortLabel: '技術' }
  ],

  // Sensitivity thresholds
  SENSITIVITY_THRESHOLDS: {
    high:     { criticalDim: 20, warnDim: 35, scamPattern: 35 },
    standard: { criticalDim: 15, warnDim: 30, scamPattern: 30 },
    low:      { criticalDim: 10, warnDim: 20, scamPattern: 20 }
  },

  integrate(clientAnalysis, aiResult) {
    const scores = {};

    if (aiResult) {
      // Blend client + AI for domain_trust and tech_safety
      scores.domain_trust = Math.round(clientAnalysis.domain_trust * 0.4 + aiResult.scores.domain_trust * 0.6);
      scores.tech_safety = Math.round(clientAnalysis.tech_safety * 0.4 + aiResult.scores.tech_safety * 0.6);
      // AI-only for other dimensions
      scores.content_safety = aiResult.scores.content_safety;
      scores.operator_transparency = aiResult.scores.operator_transparency;
      scores.claim_credibility = aiResult.scores.claim_credibility;
      scores.scam_pattern = aiResult.scores.scam_pattern;
    } else {
      // Client-only fallback
      scores.domain_trust = clientAnalysis.domain_trust;
      scores.tech_safety = clientAnalysis.tech_safety;
      scores.content_safety = 50;
      scores.operator_transparency = 50;
      scores.claim_credibility = 50;
      scores.scam_pattern = 50;
    }

    // Clamp all
    for (const k of Object.keys(scores)) {
      scores[k] = Math.max(0, Math.min(100, scores[k]));
    }

    // Load sensitivity thresholds
    const sensitivity = loadSensitivity();
    const thresholds = this.SENSITIVITY_THRESHOLDS[sensitivity] || this.SENSITIVITY_THRESHOLDS.standard;

    // Overall risk
    const avg = Object.values(scores).reduce((a, b) => a + b, 0) / 6;
    let risk;
    if (avg >= 80) risk = 'safe';
    else if (avg >= 60) risk = 'low';
    else if (avg >= 40) risk = 'medium';
    else if (avg >= 20) risk = 'high';
    else risk = 'critical';

    // Override: escalate based on critical dimensions (sensitivity-adjusted)
    const criticalDims = Object.values(scores).filter(v => v <= thresholds.criticalDim).length;
    const warnDims = Object.values(scores).filter(v => v <= thresholds.warnDim).length;
    if (criticalDims >= 2 || scores.scam_pattern <= thresholds.criticalDim) {
      // Multiple critical axes or scam pattern match → force high
      if (risk === 'safe' || risk === 'low' || risk === 'medium') risk = 'high';
    } else if (scores.scam_pattern <= thresholds.scamPattern || warnDims >= 3) {
      // Low scam pattern or many warning axes → at least medium
      if (risk === 'safe' || risk === 'low') risk = 'medium';
    } else if (criticalDims === 1 && risk === 'safe') {
      // Single critical axis on otherwise safe site → nudge to low
      risk = 'low';
    }

    // Use AI's overall_risk if available and more severe
    if (aiResult) {
      const riskOrder = ['safe','low','medium','high','critical'];
      const aiIdx = riskOrder.indexOf(aiResult.overall_risk);
      const calcIdx = riskOrder.indexOf(risk);
      if (aiIdx > calcIdx) risk = aiResult.overall_risk;
    }

    return { scores, risk };
  }
};

// ============================================================
// Radar Chart (Canvas)
// ============================================================
const RadarChart = {
  draw(canvasId, scores) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const dpr = window.devicePixelRatio || 1;
    const size = 300;
    canvas.width = size * dpr;
    canvas.height = size * dpr;
    canvas.style.width = size + 'px';
    canvas.style.height = size + 'px';
    const ctx = canvas.getContext('2d');
    ctx.scale(dpr, dpr);

    const cx = size / 2;
    const cy = size / 2;
    const r = 100;
    const dims = ScoreIntegrator.DIMENSIONS;
    const n = dims.length;
    const angleStep = (Math.PI * 2) / n;
    const startAngle = -Math.PI / 2;

    // Background
    ctx.clearRect(0, 0, size, size);

    // Grid (5 levels)
    for (let level = 1; level <= 5; level++) {
      const lr = (r * level) / 5;
      ctx.beginPath();
      for (let i = 0; i <= n; i++) {
        const angle = startAngle + angleStep * (i % n);
        const x = cx + lr * Math.cos(angle);
        const y = cy + lr * Math.sin(angle);
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.closePath();
      ctx.strokeStyle = '#E0E4E8';
      ctx.lineWidth = 1;
      ctx.stroke();
    }

    // Axis lines
    for (let i = 0; i < n; i++) {
      const angle = startAngle + angleStep * i;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.lineTo(cx + r * Math.cos(angle), cy + r * Math.sin(angle));
      ctx.strokeStyle = '#D0D4D8';
      ctx.lineWidth = 1;
      ctx.stroke();
    }

    // Data polygon
    const values = dims.map(d => (scores[d.key] || 0) / 100);
    const avg = values.reduce((a, b) => a + b, 0) / values.length * 100;

    // Determine color based on average
    let fillColor, strokeColor;
    if (avg >= 70) {
      fillColor = 'rgba(39, 174, 96, 0.25)';
      strokeColor = '#27AE60';
    } else if (avg >= 40) {
      fillColor = 'rgba(243, 156, 18, 0.25)';
      strokeColor = '#F39C12';
    } else {
      fillColor = 'rgba(231, 76, 60, 0.25)';
      strokeColor = '#E74C3C';
    }

    ctx.beginPath();
    for (let i = 0; i <= n; i++) {
      const idx = i % n;
      const angle = startAngle + angleStep * idx;
      const vr = r * values[idx];
      const x = cx + vr * Math.cos(angle);
      const y = cy + vr * Math.sin(angle);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    }
    ctx.closePath();
    ctx.fillStyle = fillColor;
    ctx.fill();
    ctx.strokeStyle = strokeColor;
    ctx.lineWidth = 2.5;
    ctx.stroke();

    // Data points
    for (let i = 0; i < n; i++) {
      const angle = startAngle + angleStep * i;
      const vr = r * values[i];
      const x = cx + vr * Math.cos(angle);
      const y = cy + vr * Math.sin(angle);
      ctx.beginPath();
      ctx.arc(x, y, 4, 0, Math.PI * 2);
      ctx.fillStyle = strokeColor;
      ctx.fill();
    }

    // Labels
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.font = '12px -apple-system, BlinkMacSystemFont, sans-serif';
    ctx.fillStyle = '#555';
    const labelR = r + 22;
    for (let i = 0; i < n; i++) {
      const angle = startAngle + angleStep * i;
      const x = cx + labelR * Math.cos(angle);
      const y = cy + labelR * Math.sin(angle);
      ctx.fillText(dims[i].shortLabel, x, y);
    }
  }
};

// ============================================================
// Progress Manager
// ============================================================
const SAFETY_TIPS = [
  // --- メール・メッセージ ---
  '知らない送信元からのメールのリンクは開かないようにしましょう',
  '「アカウントが停止されました」というメールは、まず公式サイトで確認を',
  'メールの差出人名は簡単に偽装できます。アドレスのドメインを確認しましょう',
  '添付ファイル付きの不審なメールは開かずに削除しましょう',
  'メールのリンクにマウスを乗せると、実際のURLを確認できます',
  '「至急」「緊急」で始まるメールほど、落ち着いて対処しましょう',
  '宅配不在通知のSMSのリンクは偽物の可能性があります',
  '銀行やカード会社がメールでパスワードを聞くことはありません',
  'SMSで届く認証コードは、自分が操作したとき以外は入力しないで',
  '不審なメールは転送せず、公式の問い合わせ窓口に相談しましょう',
  // --- パスワード・認証 ---
  'パスワードは使い回さず、サイトごとに異なるものを設定しましょう',
  '二要素認証（2FA）を設定すると、不正ログインのリスクが大幅に減ります',
  'パスワードマネージャーを使えば、複雑なパスワードも管理が楽です',
  '「1234」「password」などの簡単なパスワードは数秒で破られます',
  '生年月日や電話番号をパスワードに使うのは避けましょう',
  '定期的なパスワード変更より、十分な長さと複雑さが重要です',
  'ログイン画面のURLが正しいか、毎回確認する習慣をつけましょう',
  '公共のPCでログインした後は、必ずログアウトしましょう',
  'パスワードをブラウザに保存する場合は、端末のロックも忘れずに',
  'パスワードリスト攻撃を防ぐため、同じパスワードの使い回しは厳禁です',
  // --- URL・サイト確認 ---
  'URLがhttps://で始まるか確認しましょう',
  'URLに見慣れない文字列が長く続く場合は注意が必要です',
  '正規サイトのURLをブックマークしておくと、偽サイトを避けられます',
  'ドメイン名の「l」と「1」、「o」と「0」の違いに注意しましょう',
  'URLの末尾が.xyz .top .icu など見慣れないTLDは要注意です',
  '検索結果の上位に表示される広告リンクが偽サイトのこともあります',
  'QRコードの上にシールが貼られていないか確認しましょう',
  '短縮URLは展開してから開く習慣をつけましょう',
  'Wi-Fiログインページを装った偽サイトに注意しましょう',
  'リダイレクトが多いサイトは、不正な誘導の可能性があります',
  // --- ネットショッピング ---
  '特定商取引法の表記がないネットショップは要注意です',
  '相場より極端に安い商品は、偽物や詐欺の可能性があります',
  '支払い方法が銀行振込のみの通販サイトは注意が必要です',
  'レビューが極端に良いだけの商品は、サクラレビューの可能性があります',
  '通販サイトの会社住所をGoogleマップで確認してみましょう',
  '海外通販は返品・返金のハードルが高いことを覚えておきましょう',
  '初めてのショップでは少額の買い物から試すのが安全です',
  'クレジットカードの明細は定期的にチェックしましょう',
  '代引きでも届いた中身が注文と違う詐欺があります',
  'フリマアプリでは必ずアプリ内決済を利用し、外部での直接取引は避けましょう',
  // --- 投資・お金 ---
  '「確実に儲かる」投資話は詐欺の可能性が高いです',
  '「元本保証」をうたう投資商品は法律上ほぼ存在しません',
  '知人からの投資勧誘でも、マルチ商法の可能性を疑いましょう',
  '暗号資産の「必ず値上がりする」という話は信じないでください',
  'FX自動売買ツールの高額販売は、ほとんどが詐欺です',
  '投資セミナーの参加費が無料でも、高額商材の勧誘に注意',
  '「今だけ」「あなただけ」の投資話は典型的な詐欺の手口です',
  '金融庁の登録がない業者での投資は極めて危険です',
  '海外の無登録FX業者は出金できなくなるトラブルが多発しています',
  'SNSで見かける投資成功体験は、演出されたものがほとんどです',
  // --- SNS・個人情報 ---
  '個人情報を求めるサイトは、本物かどうか公式サイトから確認を',
  'SNSのDMで届く副業・投資の誘いに注意しましょう',
  'SNSのプロフィール情報から個人を特定されることがあります',
  '位置情報付きの写真をSNSに投稿すると、居場所が特定されます',
  'フォロワーが多いアカウントでも、なりすましの可能性があります',
  'オンラインで知り合った人にお金を送ることは避けましょう',
  'SNSの「診断系アプリ」でアカウント連携する前に権限を確認しましょう',
  '子どもの写真をSNSに投稿するときは位置情報と制服に注意',
  'ダイレクトメッセージのリンクは、知人からでも慎重に開きましょう',
  '退会したいサービスのアカウントは放置せず削除しましょう',
  // --- 詐欺の手口 ---
  'ウイルス感染警告が突然表示されても、慌てて電話しないでください',
  'サイトの日本語が不自然な場合、海外の詐欺サイトの可能性があります',
  '「当選しました」という通知は、応募していなければ詐欺です',
  '「未払い料金があります」という連絡は、まず公式に確認を',
  '警察や裁判所を名乗る電話でも、お金を振り込ませることはありません',
  '「被害を回復します」という勧誘は、二次被害の入り口です',
  '還付金があるとATMに誘導するのは、典型的な詐欺です',
  'マイナンバーを電話で聞き出そうとする行為は詐欺です',
  'ワンクリック詐欺で請求画面が出ても、お金を払う必要はありません',
  '架空請求のハガキが届いても、記載の電話番号には絶対に電話しないで',
  // --- 闇バイト・副業 ---
  '「簡単作業で高収入」は闇バイトの典型的な募集文句です',
  '「荷物を受け取るだけ」のバイトは犯罪に加担させられます',
  '「口座を貸すだけ」は犯罪です。自分の口座を他人に使わせないで',
  '「即日払い・日払い」を強調するバイト募集は要注意です',
  'Telegramでの仕事募集は、犯罪組織の可能性が高いです',
  '身分証の写真を送ると、脅迫や犯罪に悪用されます',
  '一度関わると抜け出せなくなるのが闇バイトの怖さです',
  '副業紹介の初期費用を請求されたら、それは副業詐欺です',
  '知らない相手に自分の銀行口座情報を教えてはいけません',
  '「マニュアル通りにやるだけ」という仕事は指示型犯罪の可能性があります',
  // --- デバイス・ソフトウェア ---
  'OSやアプリのアップデートはセキュリティ修正が含まれるため、早めに適用を',
  '公式ストア以外からアプリをインストールするのは危険です',
  '無料VPNアプリの中には通信内容を盗み見るものがあります',
  '使わなくなったアプリは定期的に削除しましょう',
  'スマホの画面ロックは必ず設定しましょう',
  'Bluetoothは使わないときはオフにしておくと安全です',
  '公共のUSB充電ポートはデータ窃取のリスクがあります',
  'PCのWebカメラは使わないときはカバーをしておくと安心です',
  '古いルーターのファームウェアは脆弱性が放置されがちです',
  'ブラウザの拡張機能は信頼できるものだけに絞りましょう',
  // --- Wi-Fi・通信 ---
  '公共Wi-Fiでのネットバンキングやカード決済は避けましょう',
  'カフェなどの無料Wi-Fiでは、VPNの利用を検討しましょう',
  '見覚えのないWi-Fiに自動接続していないか確認しましょう',
  'ホテルのWi-Fiでも、重要な情報のやりとりには注意が必要です',
  '自宅のWi-Fiパスワードは初期設定のまま使わず変更しましょう',
  // --- その他 ---
  '不審に思ったら、消費者ホットライン「188」に相談できます',
  'サイバー犯罪の被害は警察の「#9110」に相談できます',
  '国民生活センターのサイトで最新の詐欺手口を確認できます',
  '家族や友人と詐欺の手口を共有しておくと、被害を防げます',
  '「おかしいな」と思ったら、一人で判断せず誰かに相談しましょう'
];

const ProgressMgr = {
  _tipIdx: 0,
  _tipTimer: null,

  show() {
    document.getElementById('progressOverlay').hidden = false;
    this._tipIdx = Math.floor(Math.random() * SAFETY_TIPS.length);
    this._showTip();
    this._tipTimer = setInterval(() => this._showTip(), 4000);
  },

  hide() {
    document.getElementById('progressOverlay').hidden = true;
    if (this._tipTimer) { clearInterval(this._tipTimer); this._tipTimer = null; }
  },

  update(stage, pct) {
    document.getElementById('progressStage').textContent = stage;
    document.getElementById('progressBar').style.width = pct + '%';
    document.getElementById('progressPct').textContent = Math.round(pct) + '%';
  },

  _showTip() {
    document.getElementById('progressTip').textContent = SAFETY_TIPS[this._tipIdx % SAFETY_TIPS.length];
    this._tipIdx++;
  }
};

// ============================================================
// Results Renderer
// ============================================================
const ResultsRenderer = {
  RISK_LABELS: {
    safe: { text: '問題は見つかりませんでした', icon: '\u2714' },
    low: { text: '軽微な注意点があります', icon: '\u2139' },
    medium: { text: '確認をおすすめする点があります', icon: '\u26A0' },
    high: { text: '注意が必要な要素が見つかりました', icon: '\u26A0' },
    critical: { text: '複数の深刻な懸念があります', icon: '\u2718' }
  },

  render(url, integrated, aiResult, clientAnalysis, incomplete) {
    const { scores, risk } = integrated;

    // Risk banner
    const banner = document.getElementById('riskBanner');
    banner.className = 'risk-banner ' + risk;
    const rl = this.RISK_LABELS[risk] || this.RISK_LABELS.medium;
    document.getElementById('riskIcon').textContent = rl.icon;
    document.getElementById('riskLevel').textContent = rl.text;
    try { document.getElementById('riskUrl').textContent = new URL(url).hostname; } catch { document.getElementById('riskUrl').textContent = url; }

    // Radar chart
    RadarChart.draw('radarChart', scores);

    // Score bars
    const barsEl = document.getElementById('scoreBars');
    barsEl.innerHTML = '';
    ScoreIntegrator.DIMENSIONS.forEach(dim => {
      const val = Math.max(0, Math.min(100, Math.round(Number(scores[dim.key]) || 0)));
      let cls;
      if (val >= 80) cls = 'safe';
      else if (val >= 60) cls = 'low';
      else if (val >= 40) cls = 'medium';
      else if (val >= 20) cls = 'high';
      else cls = 'critical';

      barsEl.innerHTML += `
        <div class="score-bar-item">
          <div class="score-bar-label">
            <span class="score-bar-name">${this._esc(dim.label)}</span>
            <span class="score-bar-value">${val}</span>
          </div>
          <div class="score-bar-track">
            <div class="score-bar-fill ${cls}" style="width:${val}%"></div>
          </div>
        </div>`;
    });

    // Detected categories
    const catCard = document.getElementById('categoriesCard');
    const catList = document.getElementById('categoriesList');
    if (aiResult && aiResult.detected_categories && aiResult.detected_categories.length > 0) {
      catCard.hidden = false;
      const validConf = ['high','medium','low'];
      catList.innerHTML = aiResult.detected_categories.map(c => `
        <div style="margin-bottom:8px">
          <span class="category-tag ${validConf.includes(c.confidence) ? c.confidence : 'medium'}">${this._esc(c.category)}</span>
          <div class="category-evidence">${this._esc(c.evidence)}</div>
        </div>
      `).join('');
    } else {
      catCard.hidden = true;
    }

    // Findings
    const findCard = document.getElementById('findingsCard');
    const findList = document.getElementById('findingsList');
    const allFindings = [];

    // Client findings
    clientAnalysis.issues.forEach(iss => {
      allFindings.push({
        dimension: 'URL分析',
        severity: iss.severity,
        title: iss.title,
        description: iss.desc || '',
        quote: ''
      });
    });

    // AI findings
    if (aiResult && aiResult.findings) {
      aiResult.findings.forEach(f => allFindings.push(f));
    }

    if (allFindings.length > 0) {
      findCard.hidden = false;
      findList.innerHTML = allFindings.map(f => `
        <div class="finding-item">
          <div class="finding-header">
            <span class="finding-severity ${f.severity}"></span>
            <span class="finding-title">${this._esc(f.title)}</span>
            <span class="finding-dimension">${this._esc(f.dimension)}</span>
          </div>
          ${f.description ? `<div class="finding-desc">${this._esc(f.description)}</div>` : ''}
          ${f.quote ? `<div class="finding-quote">${this._esc(f.quote)}</div>` : ''}
        </div>
      `).join('');
    } else {
      findCard.hidden = true;
    }

    // Summary
    const sumCard = document.getElementById('summaryCard');
    if (aiResult && aiResult.summary) {
      sumCard.hidden = false;
      document.getElementById('summaryText').textContent = aiResult.summary;
    } else {
      sumCard.hidden = true;
    }

    // Incomplete notice
    const noticeEl = document.getElementById('incompleteNotice');
    if (incomplete) {
      noticeEl.hidden = false;
      document.getElementById('incompleteText').textContent = incomplete;
    } else {
      noticeEl.hidden = true;
    }

    showScreen('screenResults');
  },

  _esc(s) {
    if (!s) return '';
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }
};

// ============================================================
// Main Analysis Flow
// ============================================================
let isChecking = false;
async function runCheck(urlStr) {
  if (isChecking) return;
  isChecking = true;
  const config = loadConfig();
  let incomplete = null;
  let aiResult = null;
  let htmlContent = null;
  let headers = null;

  ProgressMgr.show();

  try {
    // Stage 1: URL analysis + Worker fetch in PARALLEL
    ProgressMgr.update('URL構造を分析中...', 5);
    const clientAnalysis = UrlAnalyzer.analyze(urlStr);
    ProgressMgr.update('サイトを取得中...', 15);

    let fetchData = null;
    try {
      const workerUrl = (config.workerUrl || DEFAULT_WORKER_URL).replace(/\/+$/, '');
      const fetchResp = await fetch(`${workerUrl}/fetch?url=${encodeURIComponent(urlStr)}`, {
        headers: config.apiKey ? { 'X-API-Key': config.apiKey } : {},
        signal: AbortSignal.timeout(15000)
      });
      if (fetchResp.ok) {
        fetchData = await fetchResp.json();
        if (fetchData.error) {
          incomplete = `サイトの取得に失敗しました（${fetchData.error}）。URL分析のみの部分的な結果です。`;
          fetchData = null;
        }
      } else {
        let errDetail = `HTTP ${fetchResp.status}`;
        try { const errJson = await fetchResp.json(); errDetail = errJson.error || errDetail; } catch {}
        incomplete = `サイトの取得に失敗しました（${errDetail}）。URL分析のみの部分的な結果です。`;
      }
    } catch (e) {
      incomplete = 'サイトの取得に失敗しました（' + (e.name === 'TimeoutError' ? 'タイムアウト' : e.message) + '）。URL分析のみの部分的な結果です。';
    }

    // Stage 2: Extract content from fetched HTML
    ProgressMgr.update('コンテンツを解析中...', 35);
    if (fetchData) {
      headers = fetchData.headers || null;
      if (fetchData.html) {
        htmlContent = HtmlExtractor.extract(fetchData.html, urlStr);
      }

      // Check redirects
      if (fetchData.redirected && fetchData.finalUrl && fetchData.finalUrl !== urlStr) {
        // Detect login/session redirect
        const finalLower = fetchData.finalUrl.toLowerCase();
        if (/\/(login|signin|session|auth|sso|cas|oauth|saml)\b/i.test(finalLower)) {
          incomplete = 'ログインが必要なページのため、内容を取得できませんでした。「テキスト貼り付け」モードでページ内容をコピペして分析できます。';
        }
        clientAnalysis.issues.push({
          title: 'リダイレクト検出',
          severity: 'low',
          desc: `最終URL: ${fetchData.finalUrl}`
        });
      }

      // Tech safety adjustments from extracted content
      if (htmlContent) {
        if (htmlContent.obfuscationSuspect) {
          clientAnalysis.tech_safety = Math.max(0, clientAnalysis.tech_safety - 20);
          clientAnalysis.issues.push({ title: 'スクリプト難読化の疑い', severity: 'medium', desc: 'eval/atob/fromCharCode等の難読化パターンが検出されました。' });
        }
        if (htmlContent.hiddenFormFields > 0) {
          clientAnalysis.tech_safety = Math.max(0, clientAnalysis.tech_safety - 15);
          clientAnalysis.issues.push({ title: '隠しフォーム要素', severity: 'medium', desc: `${htmlContent.hiddenFormFields}個の非表示フォーム要素があります。` });
        }
      }
    }

    // Stage 3: Gemini AI analysis
    if (config.apiKey) {
      ProgressMgr.update('AI分析中...', 55);
      try {
        aiResult = await GeminiClient.analyze(config, urlStr, clientAnalysis, htmlContent, headers);
        ProgressMgr.update('AI分析中...', 85);
      } catch (e) {
        if (!incomplete) {
          incomplete = 'AI分析に失敗しました（' + e.message.slice(0, 100) + '）。部分的な結果です。';
        } else {
          incomplete += ' AI分析も失敗しました。';
        }
      }
    } else {
      incomplete = (incomplete || '') + ' APIキーが未設定のためAI分析をスキップしました。';
    }

    // Stage 4: Integrate & render
    ProgressMgr.update('結果を統合中...', 95);
    const integrated = ScoreIntegrator.integrate(clientAnalysis, aiResult);

    ProgressMgr.update('完了', 100);
    await sleep(200);

    ProgressMgr.hide();
    ResultsRenderer.render(urlStr, integrated, aiResult, clientAnalysis, incomplete ? incomplete.trim() : null);

  } catch (e) {
    console.error('Analysis error:', e);
    ProgressMgr.hide();
    alert('分析中にエラーが発生しました: ' + (e.message || '不明なエラー'));
    showScreen('screenCheck');
  } finally {
    isChecking = false;
  }
}

// Text paste analysis mode
async function runTextCheck(urlStr, pastedText) {
  if (isChecking) return;
  const config = loadConfig();
  if (!config.apiKey) {
    alert('APIキーが設定されていません。設定画面からAPIキーを入力してください。');
    return;
  }
  isChecking = true;
  let incomplete = null;
  let aiResult = null;

  // Build minimal clientAnalysis
  let clientAnalysis = { domain_trust: 50, tech_safety: 50, issues: [] };
  if (urlStr) {
    clientAnalysis = UrlAnalyzer.analyze(urlStr);
  } else {
    incomplete = 'URLが未入力のため、URL構造分析はスキップされました。';
  }

  // Build minimal htmlContent from pasted text
  const htmlContent = {
    title: '',
    headings: [],
    bodyText: pastedText.slice(0, 10000),
    externalLinkCount: 0,
    externalDomains: [],
    forms: [],
    inlineScriptChars: 0,
    obfuscationSuspect: false,
    hiddenFormFields: 0,
    hasCompanyInfo: /会社概要|企業情報|運営会社|事務所[概名]|代表弁護士|代表取締役|代表者/i.test(pastedText),
    hasContact: /お問い合わせ|連絡先|電話番号|所在地|住所/i.test(pastedText),
    hasPrivacyPolicy: /プライバシー|個人情報保護/i.test(pastedText),
    hasCommerceLaw: /特定商取引|特商法/i.test(pastedText),
    companyInfoInContent: true,
    commerceLawInContent: /特定商取引|特商法/i.test(pastedText),
  };

  ProgressMgr.show();

  try {
    ProgressMgr.update('テキストを分析中...', 20);

    // Gemini analysis
    ProgressMgr.update('AI分析中...', 40);
    try {
      aiResult = await GeminiClient.analyze(config, urlStr || '(URLなし・テキスト直接入力)', clientAnalysis, htmlContent, null);
      ProgressMgr.update('スコアを統合中...', 85);
    } catch (e) {
      const msg = e.message || '';
      incomplete = (incomplete ? incomplete + ' ' : '') + `AI分析に失敗しました（${msg}）。部分的な結果です。`;
    }

    const integrated = ScoreIntegrator.integrate(clientAnalysis, aiResult);
    ProgressMgr.update('完了', 100);
    await sleep(200);

    ProgressMgr.hide();
    ResultsRenderer.render(urlStr || '(テキスト入力)', integrated, aiResult, clientAnalysis, incomplete ? incomplete.trim() : null);

  } catch (e) {
    console.error('Analysis error:', e);
    ProgressMgr.hide();
    alert('分析中にエラーが発生しました: ' + (e.message || '不明なエラー'));
    showScreen('screenCheck');
  } finally {
    isChecking = false;
  }
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ============================================================
// Init & Event Binding
// ============================================================
function init() {
  const config = loadConfig();

  // Determine initial screen
  if (!hasConsent()) {
    showScreen('screenConsent');
  } else if (config.apiKey) {
    showScreen('screenCheck');
  } else {
    showScreen('screenSetup');
  }

  // Remove legacy workerUrl if it matches default (privacy: don't persist default URL)
  if (config.workerUrl === DEFAULT_WORKER_URL) {
    delete config.workerUrl;
    saveConfig(config);
  }

  function validateWorkerUrl(url) {
    try {
      const u = new URL(url);
      if (u.protocol !== 'https:') { alert('Worker URLはhttps://で始まる必要があります。'); return false; }
      return true;
    } catch { alert('有効なURLを入力してください。'); return false; }
  }

  // Consent
  document.getElementById('consentCheckbox').addEventListener('change', (e) => {
    document.getElementById('btnConsent').disabled = !e.target.checked;
  });

  document.getElementById('btnConsent').addEventListener('click', () => {
    setConsent();
    const cfg = loadConfig();
    if (cfg.apiKey) {
      showScreen('screenCheck');
    } else {
      showScreen('screenSetup');
    }
  });

  // Setup save (API key only, Worker URL auto-set)
  document.getElementById('btnSetupSave').addEventListener('click', () => {
    const apiKey = document.getElementById('setupApiKey').value.trim();
    if (!apiKey) {
      alert('APIキーを入力してください。');
      return;
    }
    if (!/^AIza[A-Za-z0-9_-]{35}$/.test(apiKey)) {
      alert('APIキーの形式が正しくありません。AIzaで始まる39文字のキーを入力してください。');
      return;
    }
    const cfg = loadConfig();
    cfg.apiKey = apiKey;
    saveConfig(cfg);
    showScreen('screenCheck');
  });

  // Home
  function resetAndGoHome() {
    document.getElementById('inputUrl').value = '';
    document.getElementById('inputText').value = '';
    document.getElementById('inputTextUrl').value = '';
    document.getElementById('urlError').hidden = true;
    // Reset to URL tab
    document.querySelectorAll('.mode-tab').forEach(t => t.classList.toggle('active', t.dataset.mode === 'url'));
    document.getElementById('modeUrl').hidden = false;
    document.getElementById('modeText').hidden = true;
    const cfg = loadConfig();
    if (!hasConsent()) showScreen('screenConsent');
    else if (cfg.apiKey) showScreen('screenCheck');
    else showScreen('screenSetup');
  }

  document.getElementById('btnHome').addEventListener('click', resetAndGoHome);

  // Settings
  document.getElementById('btnSettings').addEventListener('click', () => {
    const cfg = loadConfig();
    document.getElementById('settingsApiKey').value = cfg.apiKey || '';
    document.getElementById('settingsWorkerUrl').value = cfg.workerUrl || '';
    // Set sensitivity radio (validate value to prevent selector injection)
    const sens = loadSensitivity();
    if (['high', 'standard', 'low'].includes(sens)) {
      const radio = document.querySelector(`input[name="sensitivity"][value="${sens}"]`);
      if (radio) radio.checked = true;
    }
    showScreen('screenSettings');
  });

  document.getElementById('btnSettingsSave').addEventListener('click', () => {
    const apiKey = document.getElementById('settingsApiKey').value.trim();
    const workerUrlInput = document.getElementById('settingsWorkerUrl').value.trim();
    if (!apiKey) {
      alert('APIキーを入力してください。');
      return;
    }
    const cfgToSave = { apiKey };
    if (workerUrlInput) {
      if (!validateWorkerUrl(workerUrlInput)) return;
      cfgToSave.workerUrl = workerUrlInput;
    }
    saveConfig(cfgToSave);
    // Save sensitivity
    const sensRadio = document.querySelector('input[name="sensitivity"]:checked');
    if (sensRadio) saveSensitivity(sensRadio.value);
    showScreen('screenCheck');
  });

  document.getElementById('btnSettingsBack').addEventListener('click', () => {
    const cfg = loadConfig();
    if (!hasConsent()) showScreen('screenConsent');
    else if (cfg.apiKey) showScreen('screenCheck');
    else showScreen('screenSetup');
  });

  // Show terms from settings
  document.getElementById('btnShowTerms').addEventListener('click', () => {
    showScreen('screenConsent');
    // Ensure checkbox and button reflect already-consented state
    if (hasConsent()) {
      document.getElementById('consentCheckbox').checked = true;
      document.getElementById('btnConsent').disabled = false;
    }
  });

  // Check
  document.getElementById('btnCheck').addEventListener('click', () => {
    const urlInput = document.getElementById('inputUrl');
    const errEl = document.getElementById('urlError');
    let urlStr = urlInput.value.trim();

    // Auto-prefix https
    if (urlStr && !/^https?:\/\//i.test(urlStr)) {
      urlStr = 'https://' + urlStr;
      urlInput.value = urlStr;
    }

    // Validate
    try {
      const u = new URL(urlStr);
      if (!['http:', 'https:'].includes(u.protocol)) throw new Error('invalid');
    } catch {
      errEl.textContent = '有効なURLを入力してください。';
      errEl.hidden = false;
      return;
    }

    errEl.hidden = true;
    runCheck(urlStr);
  });

  // Enter key on URL input
  document.getElementById('inputUrl').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      document.getElementById('btnCheck').click();
    }
  });

  // Mode tabs
  document.querySelectorAll('.mode-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.mode-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      const mode = tab.dataset.mode;
      document.getElementById('modeUrl').hidden = mode !== 'url';
      document.getElementById('modeText').hidden = mode !== 'text';
    });
  });

  // Text check
  document.getElementById('btnCheckText').addEventListener('click', () => {
    const errEl = document.getElementById('urlError');
    const textVal = document.getElementById('inputText').value.trim();
    let urlVal = document.getElementById('inputTextUrl').value.trim();

    if (!textVal) {
      errEl.textContent = 'サイトの内容を貼り付けてください。';
      errEl.hidden = false;
      return;
    }
    if (textVal.length < 50) {
      errEl.textContent = 'テキストが短すぎます。ページ全体をコピーしてください。';
      errEl.hidden = false;
      return;
    }

    // Auto-prefix https
    if (urlVal && !/^https?:\/\//i.test(urlVal)) {
      urlVal = 'https://' + urlVal;
      document.getElementById('inputTextUrl').value = urlVal;
    }
    // Validate URL if provided
    if (urlVal) {
      try {
        const u = new URL(urlVal);
        if (!['http:', 'https:'].includes(u.protocol)) throw new Error('invalid');
      } catch {
        urlVal = '';
      }
    }

    errEl.hidden = true;
    runTextCheck(urlVal, textVal);
  });

  // New check
  document.getElementById('btnNewCheck').addEventListener('click', resetAndGoHome);

  // Cancel check
  document.getElementById('btnCancelCheck').addEventListener('click', () => {
    isChecking = false;
    ProgressMgr.hide();
    showScreen('screenCheck');
  });
}

document.addEventListener('DOMContentLoaded', init);

})();
