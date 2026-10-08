export const EVTX_RULES = [
{
id: 'evtx-password-assignment',
description:
'Password assignment inside Windows Event XML',
scope: 'line',
regex:
/(password\s*[:=]\s*["']?)([^"'\s<]+)/gi,
replacementGroup: 2,
tokenType: 'PASSWORD'
},

{
id: 'evtx-bearer-jwt',
description:
'Bearer JWT inside Windows Event XML',
scope: 'line',
regex:
/(bearer\s+)(eyJ[a-zA-Z0-9_-]+.eyJ[a-zA-Z0-9_-]+.[a-zA-Z0-9_.-]+)/gi,
replacementGroup: 2,
tokenType: 'JWT'
},

{
id: 'evtx-api-key-assignment',
description:
'API key assignment inside Windows Event XML',
scope: 'line',
regex:
/((?:api?key|apikey|access[*-]?key)\s*[:=]\s*["']?)([A-Za-z0-9*-]{16,})(?=["'\s<]|$)/gi,
replacementGroup: 2,
tokenType: 'API_KEY'
}
];
