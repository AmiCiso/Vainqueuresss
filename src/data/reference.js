// Static reference lists used by the heuristic analyzer. These are deliberately small, human-curated
// and incomplete; they support indicators, not verdicts.

// Registrable domains the project treats as low-noise for *reputation-style* indicators only.
// Trust NEVER suppresses port, userinfo, nested-destination, download, encoding, lure or UGC indicators.
export const TRUSTED_REGISTRABLE = ['vainqueures.com', 'google.com', 'apple.com', 'cloudflare.com', 'microsoft.com', 'github.com'];

export const BRAND_DOMAINS = {
  cimb: ['cimb.com.my', 'cimbclicks.com.my', 'cimb.com', 'cimbbank.com.my'],
  maybank: ['maybank.com', 'maybank.com.my', 'maybank2u.com.my', 'maybank2u.com'],
  paypal: ['paypal.com'],
  apple: ['apple.com', 'icloud.com'],
  google: ['google.com', 'google.com.my', 'gmail.com'],
  microsoft: ['microsoft.com', 'microsoftonline.com', 'live.com', 'office.com', 'outlook.com'],
  github: ['github.com']
};
export const BRAND_SUFFIX = /^(bank|login|secure|verify|support|account|pay|online|clicks|my|2u|\d)/;
export const LOOKALIKE_TARGETS = ['maybank', 'maybank2u', 'cimbclicks', 'paypal', 'google', 'microsoft',
  'shopee', 'lazada', 'publicbank', 'bankislam', 'hongleongbank', 'facebook', 'instagram', 'whatsapp'];
export const EXTRA_LEGIT_DOMAINS = ['shopee.com.my', 'shopee.com', 'lazada.com.my', 'lazada.com', 'publicbank.com.my',
  'bankislam.com.my', 'hongleongbank.com.my', 'facebook.com', 'instagram.com', 'whatsapp.com'];

// Platforms where anyone can publish content. A reputable parent domain does not vouch for a page here.
export const UGC_HOSTS = ['sites.google.com', 'docs.google.com', 'drive.google.com', 'script.google.com',
  'storage.googleapis.com', 'github.io', 'gitlab.io', 'pages.dev', 'workers.dev', 'r2.dev', 'netlify.app',
  'vercel.app', 'web.app', 'firebaseapp.com', 'weebly.com', 'wixsite.com', 'blogspot.com', 'wordpress.com',
  'notion.site', 'herokuapp.com', 'onrender.com', 'fly.dev', 'glitch.me', 'repl.co', 'surge.sh',
  'trycloudflare.com', 'azurewebsites.net', 'azurestaticapps.net', 'githubusercontent.com', '000webhostapp.com'];

export const SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'cutt.ly', 'rb.gy', 'ow.ly', 'buff.ly', 'tiny.cc',
  'shorturl.at', 's.id', 'rebrand.ly', 'bit.do', 'v.gd', 'lnkd.in', 'forms.gle'];

export const ABUSE_TLDS = ['.top', '.xyz', '.icu', '.buzz', '.rest', '.tk', '.gq', '.cf', '.ga'];
export const DANGEROUS_EXTS = ['.apk', '.exe', '.scr', '.vbs', '.bat', '.ps1', '.iso', '.msi', '.jar', '.lnk', '.hta', '.cmd', '.dll', '.docm', '.xlsm', '.dmg', '.pkg'];
export const LURE_WORDS = ['angpao', 'hadiah', 'bonus', 'claim', 'verify-id', 'secure-login', 'wallet-reward'];

export const GOV = ['lhdn', 'kwsp', 'epf', 'jpj', 'pdrm', 'mysejahtera', 'poslaju', 'spx', 'jnt', 'tng', 'touchngo', 'tnb', 'maxis', 'celcom', 'digi', 'unifi', 'bsn', 'ambank', 'rhb', 'hlb', 'grab', 'dhl', 'fedex', 'myeg', 'perkeso', 'socso', 'sprm', 'mahkamah', 'bnm', 'kastam'];
export const REGLEGIT = ['gov.my', 'edu.my', 'mil.my', 'pos.com.my', 'tngdigital.com.my', 'touchngo.com.my', 'tnb.com.my', 'maxis.com.my', 'celcom.com.my', 'digi.com.my', 'unifi.com.my', 'bsn.com.my', 'ambank.com.my', 'rhbgroup.com', 'hlb.com.my', 'grab.com', 'dhl.com', 'fedex.com', 'myeg.com.my', 'jnt.com.my', 'jtexpress.my'];
export const KEYSTUFF = ['login', 'secure', 'verify', 'account', 'update', 'signin', 'auth', 'wallet', 'claim', 'refund', 'otp', 'support', 'billing', 'helpdesk', 'online', 'confirm', 'unlock'];
export const CRED_PARAMS = ['password', 'passwd', 'pass', 'pwd', 'otp', 'tac', 'pin', 'cvv', 'card', 'nric', 'ic', 'ssn', 'secret'];
export const REDIRECT_PARAM_NAMES = ['url', 'u', 'r', 'redirect', 'redirecturl', 'redirecturi', 'redir', 'next', 'dest', 'destination', 'target', 'goto', 'return', 'returnurl', 'returnto', 'continue', 'link', 'to', 'out', 'forward', 'callback', 'service', 'ref'];

export const MESSAGE_CUES = {
  'Urgency': /segera|urgent|immediately|dalam masa \d+|within \d+|expire|tamat tempoh|dibekukan|suspend|disekat|blocked|last warning|notis akhir/i,
  'Reward': /tahniah|congratulation|hadiah|menang|you won|angpao|bonus|refund|pulangan|free gift/i,
  'Authority': /lhdn|pdrm|bank negara|jpj|mahkamah|saman|waran|polis|police|court|kastam|customs|kwsp|epf/i,
  'Call-to-action': /klik|click|tekan|sahkan|verify|kemaskini|update your|muat turun|download|install|log ?in/i,
  'Sensitive request': /\btac\b|\botp\b|\bpin\b|kata laluan|password|no\.? ?kad|card number|nric|no\.? ?ic|cvv/i,
  'Secrecy': /jangan beritahu|do not tell|don't tell|rahsia|confidential/i
};
