"""
ScamShield detection engine.

Everything here is pure Python (no external APIs), so it is fast, testable,
and works offline during a demo.

  * detect_type()      -> guesses whether a query is a phone, URL, email or name
  * normalize()        -> canonical form so "(437) 555-0142" == "437.555.0142"
  * inspect_identifier -> heuristic red flags (lookalike domains, risky area codes...)
  * analyze_message()  -> highlights scam language in a pasted text / email / DM
  * extract_identifiers() -> pulls phones, links and emails out of a message
"""
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

PHONE, URL, EMAIL, NAME = 'phone', 'url', 'email', 'name'

EMAIL_RE = re.compile(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}')
URL_RE = re.compile(
    r'(?:(?:https?://)|(?:www\.))[^\s<>"\']+|'
    r'\b[a-z0-9][a-z0-9\-]{0,62}(?:\.[a-z0-9\-]{1,63})*\.(?:com|ca|net|org|info|xyz|top|click|shop|online|site|live|io|co|biz|me|app|link|support|help|store|vip|icu|cc|tk)\b(?:/[^\s<>"\']*)?',
    re.I,
)
PHONE_RE = re.compile(r'(?<!\d)(?:\+?1[\s.\-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}(?!\d)')


# --------------------------------------------------------------------------- #
#  Type detection + normalisation
# --------------------------------------------------------------------------- #
def detect_type(value: str) -> str:
    v = (value or '').strip()
    if not v:
        return NAME
    if EMAIL_RE.fullmatch(v):
        return EMAIL
    digits = re.sub(r'\D', '', v)
    if re.fullmatch(r'[\d\s().+\-]+', v) and 10 <= len(digits) <= 11:
        return PHONE
    if ' ' not in v and (v.lower().startswith(('http://', 'https://', 'www.')) or re.search(r'\.[a-z]{2,}(/|$)', v.lower())):
        return URL
    return NAME


def domain_of(value: str) -> str:
    v = value.strip().lower()
    if '@' in v and not v.startswith('http'):
        return v.split('@', 1)[1]
    if not v.startswith(('http://', 'https://')):
        v = 'http://' + v
    host = urlparse(v).hostname or ''
    return host[4:] if host.startswith('www.') else host


def normalize(value: str, kind: str | None = None) -> str:
    kind = kind or detect_type(value)
    v = (value or '').strip()
    if kind == PHONE:
        digits = re.sub(r'\D', '', v)
        return digits[-10:] if len(digits) >= 10 else digits
    if kind == URL:
        return domain_of(v)
    if kind == EMAIL:
        return v.lower()
    return re.sub(r'\s+', ' ', v.lower())


def pretty_phone(digits: str) -> str:
    if len(digits) == 10:
        return f'({digits[:3]}) {digits[3:6]}-{digits[6:]}'
    return digits


# --------------------------------------------------------------------------- #
#  Heuristic inspection of a single identifier
# --------------------------------------------------------------------------- #
@dataclass
class Signal:
    label: str
    detail: str
    weight: int          # contribution to the 0-100 risk score
    level: str = 'warn'  # 'warn' | 'danger' | 'info' | 'good'


# Brands Canadians are commonly impersonated as, with their official domains.
BRANDS = {
    'cra': ['canada.ca'], 'canadarevenue': ['canada.ca'], 'servicecanada': ['canada.ca'],
    'ircc': ['canada.ca'], 'rcmp': ['rcmp-grc.gc.ca', 'rcmp.ca'],
    'canadapost': ['canadapost.ca', 'canadapost-postescanada.ca'],
    'interac': ['interac.ca'], 'rbc': ['rbc.com', 'rbcroyalbank.com'],
    'td': ['td.com', 'tdcanadatrust.com'], 'scotiabank': ['scotiabank.com'],
    'bmo': ['bmo.com'], 'cibc': ['cibc.com'], 'desjardins': ['desjardins.com'],
    'paypal': ['paypal.com', 'paypal.ca'], 'amazon': ['amazon.ca', 'amazon.com'],
    'apple': ['apple.com', 'icloud.com'], 'microsoft': ['microsoft.com', 'live.com', 'outlook.com'],
    'netflix': ['netflix.com'], 'kijiji': ['kijiji.ca'], 'facebook': ['facebook.com'],
    'instagram': ['instagram.com'], 'indeed': ['indeed.com', 'indeed.ca'],
    'linkedin': ['linkedin.com'], 'rogers': ['rogers.com'], 'bell': ['bell.ca'],
    'telus': ['telus.com'], 'presto': ['prestocard.ca'], 'osap': ['ontario.ca'],
    '407etr': ['407etr.com'], 'ups': ['ups.com'], 'fedex': ['fedex.com'], 'dhl': ['dhl.com'],
}
RISKY_TLDS = {'xyz', 'top', 'click', 'shop', 'online', 'site', 'live', 'vip', 'icu',
              'tk', 'ml', 'ga', 'cf', 'gq', 'buzz', 'rest', 'support', 'help', 'link', 'cc'}
SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'cutt.ly', 'is.gd', 'rb.gy', 'shorturl.at', 'tiny.cc', 'ow.ly'}
FREE_MAIL = {'gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com', 'yahoo.ca', 'icloud.com',
             'proton.me', 'protonmail.com', 'aol.com', 'gmx.com', 'mail.com', 'live.com'}
BAIT_WORDS = ['secure', 'verify', 'login', 'signin', 'account', 'update', 'refund',
              'support', 'billing', 'wallet', 'claim', 'prize', 'unlock', 'alert']
# Caribbean / overseas area codes behind "one-ring" and lottery call-back scams.
ONE_RING_AREA_CODES = {'809': 'Dominican Republic', '829': 'Dominican Republic', '849': 'Dominican Republic',
                       '876': 'Jamaica', '473': 'Grenada', '284': 'British Virgin Islands',
                       '649': 'Turks & Caicos', '268': 'Antigua', '664': 'Montserrat', '767': 'Dominica'}
CANADIAN_AREA_CODES = {
    '204', '226', '236', '249', '250', '257', '263', '289', '306', '343', '354', '365', '367', '368',
    '382', '403', '416', '418', '428', '431', '437', '438', '450', '468', '474', '506', '514', '519',
    '548', '579', '581', '584', '587', '604', '613', '639', '647', '672', '683', '705', '709', '742',
    '753', '778', '780', '782', '807', '819', '825', '867', '873', '879', '902', '905', '942'}
TOLL_FREE = {'800', '833', '844', '855', '866', '877', '888'}

HOMOGLYPHS = str.maketrans({'0': 'o', '1': 'l', '3': 'e', '5': 's', '7': 't', '@': 'a', '$': 's'})


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _is_official(host: str, officials: list[str]) -> bool:
    return any(host == d or host.endswith('.' + d) for d in officials)


def brand_impersonation(host: str):
    """Return (brand, how) if the host imitates a known brand, else None."""
    if not host:
        return None
    all_official = [d for ds in BRANDS.values() for d in ds]
    if _is_official(host, all_official):
        return None
    labels = host.split('.')
    core = '.'.join(labels[:-1]) if len(labels) > 1 else host
    flat = core.replace('-', '').replace('.', '')
    deglyphed = flat.translate(HOMOGLYPHS).replace('rn', 'm').replace('vv', 'w')
    for brand, officials in BRANDS.items():
        if len(brand) <= 3:
            # short brands (td, cra, bmo...) only when a separate word in the host
            tokens = re.split(r'[\-.]', core)
            if brand in tokens or brand in [t.translate(HOMOGLYPHS) for t in tokens]:
                return brand, 'uses the name'
            continue
        if brand in flat:
            return brand, 'uses the name'
        if brand in deglyphed:
            return brand, 'swaps look-alike characters into'
        for token in re.split(r'[\-.]', core):
            t = token.translate(HOMOGLYPHS)
            if len(t) >= 4 and abs(len(t) - len(brand)) <= 2 and 0 < _levenshtein(t, brand) <= (1 if len(brand) < 6 else 2):
                return brand, 'is one or two letters off from'
    return None


def inspect_identifier(value: str, kind: str | None = None) -> list[Signal]:
    kind = kind or detect_type(value)
    out: list[Signal] = []
    if kind == PHONE:
        d = normalize(value, PHONE)
        if len(d) != 10:
            out.append(Signal('Unusual number', 'Not a standard 10-digit North American number.', 10))
            return out
        ac = d[:3]
        if ac in ONE_RING_AREA_CODES:
            out.append(Signal('Overseas "one-ring" area code',
                              f'{ac} looks domestic but dials {ONE_RING_AREA_CODES[ac]}. Calling back can cost '
                              f'international rates; common in lottery and missed-call scams.', 35, 'danger'))
        elif ac in TOLL_FREE:
            out.append(Signal('Toll-free number', 'Easy to rent and spoof; scammers often pose as banks or the CRA '
                              'using toll-free lines. Verify on the official website.', 8, 'info'))
        elif ac in CANADIAN_AREA_CODES:
            out.append(Signal('Canadian area code', f'{ac} is a Canadian area code. Note that caller ID can be spoofed.', 0, 'info'))
    elif kind in (URL, EMAIL):
        host = domain_of(value)
        tld = host.rsplit('.', 1)[-1] if '.' in host else ''
        if kind == EMAIL:
            local = value.split('@', 1)[0].lower()
            if host in FREE_MAIL:
                claimed = next((b for b in BRANDS if len(b) > 2 and b in local.replace('.', '').replace('_', '')), None)
                if claimed:
                    out.append(Signal('Free email posing as an organization',
                                      f'Claims to be "{claimed.upper()}" but uses a free {host} inbox. '
                                      f'Real organizations email from their own domain.', 35, 'danger'))
                else:
                    out.append(Signal('Free email provider', f'{host} accounts take seconds to create.', 5, 'info'))
        if host in SHORTENERS:
            out.append(Signal('Link shortener', 'The real destination is hidden. Expand it before clicking.', 20))
        if host.startswith('xn--') or '.xn--' in host:
            out.append(Signal('Punycode domain', 'Uses international characters that can mimic Latin letters.', 30, 'danger'))
        if re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', host):
            out.append(Signal('Raw IP address', 'Legitimate sites almost never link to a bare IP address.', 30, 'danger'))
        imp = brand_impersonation(host) if host not in FREE_MAIL else None
        if imp:
            brand, how = imp
            official = ', '.join(BRANDS[brand])
            out.append(Signal('Possible brand impersonation',
                              f'This domain {how} "{brand}" but is not an official domain ({official}).', 40, 'danger'))
        if tld in RISKY_TLDS:
            out.append(Signal(f'High-abuse ending ".{tld}"', 'Cheap domain endings are heavily used for throwaway scam sites.', 15))
        if host.count('-') >= 2:
            out.append(Signal('Many hyphens', 'Long hyphenated domains (secure-login-update...) are a phishing pattern.', 10))
        baits = [w for w in BAIT_WORDS if w in host]
        if baits and kind == URL:
            out.append(Signal('Bait words in domain', 'Contains: ' + ', '.join(baits) + '.', 8 * min(len(baits), 2)))
        if kind == URL and value.lower().startswith('http://'):
            out.append(Signal('Not encrypted', 'Link uses http:// instead of https://.', 8))
        if host and not out:
            out.append(Signal('No structural red flags', 'The address itself looks ordinary. Still check community reports.', 0, 'good'))
    return out


# --------------------------------------------------------------------------- #
#  Message analyser
# --------------------------------------------------------------------------- #
RULES = [
    # (category, weight, regex)
    ('Urgency & pressure', 10, r'\b(act now|urgent(ly)?|immediately|right away|within (24|48) hours|today only|final (notice|warning)|last chance|expire[sd]?|suspended|deadline)\b'),
    ('Threats', 15, r'\b(arrest(ed)?|warrant|police|legal action|deport(ed|ation)?|lawsuit|jail|frozen|freeze your|penalt(y|ies))\b'),
    ('Unusual payment', 20, r'\b(gift ?cards?|itunes|google play cards?|steam cards?|bitcoin|btc|crypto(currency)?|usdt|wire transfer|western union|moneygram|bitcoin atm|e-?transfer (a |the )?(deposit|fee))\b'),
    ('Pay first', 18, r'\b(pay (a |the )?(small )?(fee|deposit)|deposit (first|before)|upfront|up-front|processing fee|training kit|starter kit|release fee|admin(istration)? fee|send (the )?deposit)\b'),
    ('Government impersonation', 15, r'\b(cra|canada revenue|revenue agency|service canada|ircc|immigration (canada|officer)|rcmp|sin number|social insurance)\b'),
    ('Too good to be true', 12, r'(\$\s?\d{2,3}\s?(/|per )\s?(hr|hour)|\bno experience\b|\bguaranteed\b|\byou(\'ve| have)? won\b|\bwinner\b|\bprize\b|\blottery\b|\bfree (iphone|gift)\b|\bdouble your\b|\bpassive income\b|\brisk[- ]free\b)'),
    ('Credential / data request', 15, r'\b(verify your (account|identity)|confirm your (details|identity|account)|password|one[- ]time (code|password)|otp|verification code|banking (info|details)|card number|pin\b|log ?in (here|below|now))'),
    ('Suspicious link prompt', 8, r'\b(click (the |this )?(link|here)|tap (the |this )?link|follow the link)\b'),
    ('Rental red flags', 15, r'\b(out of (the )?(country|town)|can(\'t|not) show (you )?(the )?(unit|place|apartment)|keys? (by|in the) (mail|courier)|no viewing|sight unseen)\b'),
    ('Job scam patterns', 12, r'\b(work from home|data entry|personal assistant|mystery shopper|reshipping|package forwarding|cheque deposit|deposit (the|a) (cheque|check)|telegram|whatsapp interview)\b'),
    ('Secrecy', 12, r'\b(don\'t tell|do not tell|keep (this|it) (secret|confidential|between us)|don\'t contact your bank)\b'),
    ('Generic greeting', 4, r'\b(dear (customer|user|client|sir|madam|applicant)|valued customer)\b'),
]
COMPILED = [(c, w, re.compile(p, re.I)) for c, w, p in RULES]

TIPS = {
    'Unusual payment': 'No real government agency, employer or landlord asks for gift cards or crypto.',
    'Pay first': 'Legitimate employers never charge you to start a job.',
    'Government impersonation': 'The CRA will not threaten arrest or demand immediate payment by text.',
    'Threats': 'Pressure and threats are designed to stop you from thinking. Hang up and call the official number.',
    'Credential / data request': 'Never share one-time codes or passwords. Your bank will never ask for them.',
    'Rental red flags': 'Never pay a deposit before viewing the unit in person and meeting the landlord.',
    'Job scam patterns': 'Interviews held only over Telegram/WhatsApp and cheque-deposit tasks are classic job scams.',
    'Too good to be true': 'If the pay or prize is far above normal, it is bait.',
    'Urgency & pressure': 'Slow down. Real organizations give you time to verify.',
    'Secrecy': 'Being told to keep it secret, even from your bank, is a major warning sign.',
}


@dataclass
class Analysis:
    text: str
    score: int = 0
    hits: list = field(default_factory=list)          # (category, matched text)
    categories: dict = field(default_factory=dict)    # category -> count
    spans: list = field(default_factory=list)         # (start, end, category)
    identifiers: list = field(default_factory=list)   # (kind, raw, normalized)
    tips: list = field(default_factory=list)

    @property
    def verdict(self):
        return verdict_for(self.score)


def verdict_for(score: int):
    if score >= 70:
        return ('High risk', 'danger')
    if score >= 40:
        return ('Suspicious', 'warn')
    if score >= 15:
        return ('Some warning signs', 'caution')
    return ('No obvious red flags', 'good')


def extract_identifiers(text: str):
    found, seen = [], set()
    for m in EMAIL_RE.finditer(text):
        n = normalize(m.group(), EMAIL)
        if n not in seen:
            seen.add(n); found.append((EMAIL, m.group(), n))
    email_spans = [m.span() for m in EMAIL_RE.finditer(text)]
    for m in URL_RE.finditer(text):
        if any(a <= m.start() < b for a, b in email_spans):
            continue
        raw = m.group().rstrip('.,);!?')
        n = normalize(raw, URL)
        if n and n not in seen:
            seen.add(n); found.append((URL, raw, n))
    for m in PHONE_RE.finditer(text):
        n = normalize(m.group(), PHONE)
        if len(n) == 10 and n not in seen:
            seen.add(n); found.append((PHONE, m.group().strip(), n))
    return found


def analyze_message(text: str) -> Analysis:
    a = Analysis(text=text or '')
    for cat, weight, rx in COMPILED:
        for m in rx.finditer(a.text):
            a.spans.append((m.start(), m.end(), cat))
            a.hits.append((cat, m.group()))
            a.categories[cat] = a.categories.get(cat, 0) + 1
    score = 0
    for cat, count in a.categories.items():
        w = next(w for c, w, _ in COMPILED if c == cat)
        score += w + (w // 3) * min(count - 1, 2)   # diminishing returns for repeats
    a.identifiers = extract_identifiers(a.text)
    for kind, raw, _ in a.identifiers:
        score += sum(s.weight for s in inspect_identifier(raw, kind)) // 2
    if len(a.categories) >= 3:
        score += 10   # several independent tactics together is a strong signal
    a.score = min(100, score)
    a.tips = [TIPS[c] for c in a.categories if c in TIPS][:4]
    # remove overlapping spans (keep the first / longest)
    a.spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))
    merged, last_end = [], -1
    for s in a.spans:
        if s[0] >= last_end:
            merged.append(s); last_end = s[1]
    a.spans = merged
    return a
