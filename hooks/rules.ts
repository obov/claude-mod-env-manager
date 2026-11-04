// Generated from gitleaks' default config (config/gitleaks.toml at
// gitleaks/gitleaks@5f6ec56cfa6f), its Go regexes rewritten for JavaScript:
// case-insensitive parts expanded to [aA] classes, (?s) dots as [\s\S].
// Rules scoped to a file path (.tf, nuget.config, k8s yaml) are left out:
// a prompt has no path. Sample keys in allowlists are written AI[z]a... so
// secret scanners do not flag this file. Do not edit by hand: regenerate.
//
// gitleaks is MIT licensed:
// MIT License
// Copyright (c) 2019 Zachary Rice
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

export type RawAllow = { target: string; regexes: string[]; stopwords: string[] }
export type RawRule = { id: string; regex: string; keywords: string[]; entropy: number; secretGroup: number; allow: RawAllow[] }

export const GITLEAKS_RULES: RawRule[] = [
{
"id": "1password-secret-key",
"regex": "\\bA3-[A-Z0-9]{6}-(?:(?:[A-Z0-9]{11})|(?:[A-Z0-9]{6}-[A-Z0-9]{5}))-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\\b",
"keywords": [
"a3-"
],
"entropy": 3.8,
"secretGroup": 0,
"allow": []
},
{
"id": "1password-service-account-token",
"regex": "ops_eyJ[a-zA-Z0-9+/]{250,}={0,3}",
"keywords": [
"ops_"
],
"entropy": 4,
"secretGroup": 0,
"allow": []
},
{
"id": "adafruit-api-key",
"regex": "[\\w.-]{0,50}?(?:[aA][dD][aA][fF][rR][uU][iI][tT])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9_-]{32})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"adafruit"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "adobe-client-id",
"regex": "[\\w.-]{0,50}?(?:[aA][dD][oO][bB][eE])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-fA-F0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"adobe"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "adobe-client-secret",
"regex": "\\b(p8e-[a-zA-Z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"p8e-"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "age-secret-key",
"regex": "AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}",
"keywords": [
"age-secret-key-1"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "airtable-api-key",
"regex": "[\\w.-]{0,50}?(?:[aA][iI][rR][tT][aA][bB][lL][eE])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{17})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"airtable"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "airtable-personnal-access-token",
"regex": "\\b(pat[a-zA-Z0-9]{14}\\.[a-f0-9]{64})\\b",
"keywords": [
"airtable"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "algolia-api-key",
"regex": "[\\w.-]{0,50}?(?:[aA][lL][gG][oO][lL][iI][aA])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"algolia"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "alibaba-access-key-id",
"regex": "\\b(LTAI[a-zA-Z0-9]{20})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"ltai"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "alibaba-secret-key",
"regex": "[\\w.-]{0,50}?(?:[aA][lL][iI][bB][aA][bB][aA])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{30})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"alibaba"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "anthropic-admin-api-key",
"regex": "\\b(sk-ant-admin01-[a-zA-Z0-9_\\-]{93}AA)(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"sk-ant-admin01"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "anthropic-api-key",
"regex": "\\b(sk-ant-api03-[a-zA-Z0-9_\\-]{93}AA)(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"sk-ant-api03"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "artifactory-api-key",
"regex": "\\bAKCp[A-Za-z0-9]{69}\\b",
"keywords": [
"akcp"
],
"entropy": 4.5,
"secretGroup": 0,
"allow": []
},
{
"id": "artifactory-reference-token",
"regex": "\\bcmVmd[A-Za-z0-9]{59}\\b",
"keywords": [
"cmvmd"
],
"entropy": 4.5,
"secretGroup": 0,
"allow": []
},
{
"id": "asana-client-id",
"regex": "[\\w.-]{0,50}?(?:[aA][sS][aA][nN][aA])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9]{16})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"asana"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "asana-client-secret",
"regex": "[\\w.-]{0,50}?(?:[aA][sS][aA][nN][aA])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"asana"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "atlassian-api-token",
"regex": "[\\w.-]{0,50}?(?:(?:ATLASSIAN|[Aa]tlassian)|(?:CONFLUENCE|[Cc]onfluence)|(?:JIRA|[Jj]ira))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{20}[a-fA-F0-9]{4})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)|\\b([Aa][Tt][Aa][Tt][Tt]3[A-Za-za-zA-Z0-9_\\-=]{186})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"atlassian",
"confluence",
"jira",
"atatt3"
],
"entropy": 3.5,
"secretGroup": 0,
"allow": []
},
{
"id": "authress-service-client-access-key",
"regex": "\\b((?:sc|ext|scauth|authress)_[a-zA-Z0-9]{5,30}\\.[a-zA-Z0-9]{4,6}\\.(?:acc)[_-][a-zA-Z0-9-]{10,32}\\.[a-zA-Z0-9+/_=-]{30,120})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"sc_",
"ext_",
"scauth_",
"authress_"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "aws-access-token",
"regex": "\\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\\b",
"keywords": [
"a3t",
"akia",
"asia",
"abia",
"acca"
],
"entropy": 3,
"secretGroup": 0,
"allow": [
{
"target": "secret",
"regexes": [
".+EXAMPLE$"
],
"stopwords": []
}
]
},
{
"id": "aws-amazon-bedrock-api-key-long-lived",
"regex": "\\b(ABSK[A-Za-z0-9+/]{109,269}={0,2})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"absk"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "aws-amazon-bedrock-api-key-short-lived",
"regex": "bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t",
"keywords": [
"bedrock-api-key-"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "azure-ad-client-secret",
"regex": "(?:^|[\\\\'\"\\x60\\s>=:(,)])([a-zA-Z0-9_~.]{3}\\dQ~[a-zA-Z0-9_~.-]{31,34})(?:$|[\\\\'\"\\x60\\s<),])",
"keywords": [
"q~"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "beamer-api-token",
"regex": "[\\w.-]{0,50}?(?:[bB][eE][aA][mM][eE][rR])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([bB]_[a-zA-Z0-9=_\\-]{44})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"beamer"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "bitbucket-client-id",
"regex": "[\\w.-]{0,50}?(?:[bB][iI][tT][bB][uU][cC][kK][eE][tT])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"bitbucket"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "bitbucket-client-secret",
"regex": "[\\w.-]{0,50}?(?:[bB][iI][tT][bB][uU][cC][kK][eE][tT])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9=_\\-]{64})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"bitbucket"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "bittrex-access-key",
"regex": "[\\w.-]{0,50}?(?:[bB][iI][tT][tT][rR][eE][xX])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"bittrex"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "bittrex-secret-key",
"regex": "[\\w.-]{0,50}?(?:[bB][iI][tT][tT][rR][eE][xX])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"bittrex"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "cisco-meraki-api-key",
"regex": "[\\w.-]{0,50}?(?:[\\w.-]{0,50}?(?:(?:[Mm]eraki|MERAKI))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-f]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"meraki"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "clickhouse-cloud-api-secret-key",
"regex": "\\b(4b1d[A-Za-z0-9]{38})\\b",
"keywords": [
"4b1d"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "clojars-api-token",
"regex": "[Cc][Ll][Oo][Jj][Aa][Rr][Ss]_[a-zA-Z0-9]{60}",
"keywords": [
"clojars_"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "cloudflare-api-key",
"regex": "[\\w.-]{0,50}?(?:[cC][lL][oO][uU][dD][fF][lL][aA][rR][eE])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9_-]{40})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"cloudflare"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "cloudflare-global-api-key",
"regex": "[\\w.-]{0,50}?(?:[cC][lL][oO][uU][dD][fF][lL][aA][rR][eE])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-fA-F0-9]{37})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"cloudflare"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "cloudflare-origin-ca-key",
"regex": "\\b(v1\\.0-[a-f0-9]{24}-[a-f0-9]{146})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"cloudflare",
"v1.0-"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "codecov-access-token",
"regex": "[\\w.-]{0,50}?(?:[cC][oO][dD][eE][cC][oO][vV])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"codecov"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "cohere-api-token",
"regex": "[\\w.-]{0,50}?(?:[\\w.-]{0,50}?(?:[cC][oO][hH][eE][rR][eE]|[Cc][Oo]_[Aa][Pp][Ii]_[Kk][Ee][Yy])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"cohere",
"co_api_key"
],
"entropy": 4,
"secretGroup": 0,
"allow": []
},
{
"id": "coinbase-access-token",
"regex": "[\\w.-]{0,50}?(?:[cC][oO][iI][nN][bB][aA][sS][eE])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9_-]{64})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"coinbase"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "confluent-access-token",
"regex": "[\\w.-]{0,50}?(?:[cC][oO][nN][fF][lL][uU][eE][nN][tT])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{16})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"confluent"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "confluent-secret-key",
"regex": "[\\w.-]{0,50}?(?:[cC][oO][nN][fF][lL][uU][eE][nN][tT])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"confluent"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "contentful-delivery-api-token",
"regex": "[\\w.-]{0,50}?(?:[cC][oO][nN][tT][eE][nN][tT][fF][uU][lL])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9=_\\-]{43})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"contentful"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "curl-auth-header",
"regex": "\\bcurl\\b(?:.*?|.*?(?:[\\r\\n]{1,2}.*?){1,5})[ \\t\\n\\r](?:-H|--header)(?:=|[ \\t]{0,5})(?:\"(?:[Aa][uU][tT][hH][oO][rR][iI][zZ][aA][tT][iI][oO][nN]:[ \\t]{0,5}(?:[Bb][aA][sS][iI][cC][ \\t]([a-zA-Z0-9+/]{8,}={0,3})|(?:[Bb][eE][aA][rR][eE][rR]|(?:[Aa][pP][iI]-)?[Tt][oO][kK][eE][nN])[ \\t]([\\w=~@.+/-]{8,})|([\\w=~@.+/-]{8,}))|(?:(?:[Xx]-(?:[a-zA-Z]+-)?)?(?:[Aa][pP][iI]-?)?(?:[Kk][eE][yY]|[Tt][oO][kK][eE][nN])):[ \\t]{0,5}([\\w=~@.+/-]{8,}))\"|'(?:[Aa][uU][tT][hH][oO][rR][iI][zZ][aA][tT][iI][oO][nN]:[ \\t]{0,5}(?:[Bb][aA][sS][iI][cC][ \\t]([a-zA-Z0-9+/]{8,}={0,3})|(?:[Bb][eE][aA][rR][eE][rR]|(?:[Aa][pP][iI]-)?[Tt][oO][kK][eE][nN])[ \\t]([\\w=~@.+/-]{8,})|([\\w=~@.+/-]{8,}))|(?:(?:[Xx]-(?:[a-zA-Z]+-)?)?(?:[Aa][pP][iI]-?)?(?:[Kk][eE][yY]|[Tt][oO][kK][eE][nN])):[ \\t]{0,5}([\\w=~@.+/-]{8,}))')(?:\\B|\\s|$)",
"keywords": [
"curl"
],
"entropy": 2.75,
"secretGroup": 0,
"allow": []
},
{
"id": "curl-auth-user",
"regex": "\\bcurl\\b(?:.*|.*(?:[\\r\\n]{1,2}.*){1,5})[ \\t\\n\\r](?:-u|--user)(?:=|[ \\t]{0,5})(\"(:[^\"]{3,}|[^:\"]{3,}:|[^:\"]{3,}:[^\"]{3,})\"|'([^:']{3,}:[^']{3,})'|((?:\"[^\"]{3,}\"|'[^']{3,}'|[\\w$@.-]+):(?:\"[^\"]{3,}\"|'[^']{3,}'|[\\w${}@.-]+)))(?:\\s|$)",
"keywords": [
"curl"
],
"entropy": 2,
"secretGroup": 0,
"allow": [
{
"target": "secret",
"regexes": [
"[^:]+:(?:change(?:it|me)|pass(?:word)?|pwd|test|token|\\*+|x+)",
"['\"]?<[^>]+>['\"]?:['\"]?<[^>]+>|<[^:]+:[^>]+>['\"]?",
"[^:]+:\\[[^\\]]+]",
"['\"]?[^:]+['\"]?:['\"]?\\$(?:\\d|\\w+|\\{(?:\\d|\\w+)\\})['\"]?",
"\\$\\([^)]+\\):\\$\\([^)]+\\)",
"['\"]?\\$?\\{\\{[^}]+\\}\\}['\"]?:['\"]?\\$?\\{\\{[^}]+\\}\\}['\"]?"
],
"stopwords": []
}
]
},
{
"id": "databricks-api-token",
"regex": "\\b(dapi[a-f0-9]{32}(?:-\\d)?)(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"dapi"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "datadog-access-token",
"regex": "[\\w.-]{0,50}?(?:[dD][aA][tT][aA][dD][oO][gG])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{40})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"datadog"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "defined-networking-api-token",
"regex": "[\\w.-]{0,50}?(?:[dD][nN][kK][eE][yY])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([dD][nN][kK][eE][yY]-[a-zA-Z0-9=_\\-]{26}-[a-zA-Z0-9=_\\-]{52})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"dnkey"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "digitalocean-access-token",
"regex": "\\b(doo_v1_[a-f0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"doo_v1_"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "digitalocean-pat",
"regex": "\\b(dop_v1_[a-f0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"dop_v1_"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "digitalocean-refresh-token",
"regex": "\\b([dD][oO][rR]_[vV]1_[a-fA-F0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"dor_v1_"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "discord-api-token",
"regex": "[\\w.-]{0,50}?(?:[dD][iI][sS][cC][oO][rR][dD])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-fA-F0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"discord"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "discord-client-id",
"regex": "[\\w.-]{0,50}?(?:[dD][iI][sS][cC][oO][rR][dD])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9]{18})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"discord"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "discord-client-secret",
"regex": "[\\w.-]{0,50}?(?:[dD][iI][sS][cC][oO][rR][dD])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9=_\\-]{32})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"discord"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "doppler-api-token",
"regex": "dp\\.pt\\.[a-zA-Z0-9]{43}",
"keywords": [
"dp.pt."
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "droneci-access-token",
"regex": "[\\w.-]{0,50}?(?:[dD][rR][oO][nN][eE][cC][iI])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"droneci"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "dropbox-api-token",
"regex": "[\\w.-]{0,50}?(?:[dD][rR][oO][pP][bB][oO][xX])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{15})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"dropbox"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "dropbox-long-lived-api-token",
"regex": "[\\w.-]{0,50}?(?:[dD][rR][oO][pP][bB][oO][xX])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{11}([Aa][Aa][Aa][Aa][Aa][Aa][Aa][Aa][Aa][Aa])[a-zA-Z0-9\\-_=]{43})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"dropbox"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "dropbox-short-lived-api-token",
"regex": "[\\w.-]{0,50}?(?:[dD][rR][oO][pP][bB][oO][xX])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([sS][lL]\\.[a-zA-Z0-9\\-=_]{135})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"dropbox"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "duffel-api-token",
"regex": "duffel_(?:test|live)_[a-zA-Z0-9_\\-=]{43}",
"keywords": [
"duffel_"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "dynatrace-api-token",
"regex": "dt0c01\\.[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{64}",
"keywords": [
"dt0c01."
],
"entropy": 4,
"secretGroup": 0,
"allow": []
},
{
"id": "easypost-api-token",
"regex": "\\bEZAK[a-zA-Z0-9]{54}\\b",
"keywords": [
"ezak"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "easypost-test-api-token",
"regex": "\\bEZTK[a-zA-Z0-9]{54}\\b",
"keywords": [
"eztk"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "etsy-access-token",
"regex": "[\\w.-]{0,50}?(?:(?:ETSY|[Ee]tsy))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{24})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"etsy"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "facebook-access-token",
"regex": "\\b(\\d{15,16}(\\||%)[0-9a-zA-Z\\-_]{27,40})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"facebook"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "facebook-page-access-token",
"regex": "\\b(EAA[MC][a-zA-Z0-9]{100,})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"eaam",
"eaac"
],
"entropy": 4,
"secretGroup": 0,
"allow": []
},
{
"id": "facebook-secret",
"regex": "[\\w.-]{0,50}?(?:[fF][aA][cC][eE][bB][oO][oO][kK])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-fA-F0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"facebook"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "fastly-api-token",
"regex": "[\\w.-]{0,50}?(?:[fF][aA][sS][tT][lL][yY])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9=_\\-]{32})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"fastly"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "finicity-api-token",
"regex": "[\\w.-]{0,50}?(?:[fF][iI][nN][iI][cC][iI][tT][yY])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-fA-F0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"finicity"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "finicity-client-secret",
"regex": "[\\w.-]{0,50}?(?:[fF][iI][nN][iI][cC][iI][tT][yY])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{20})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"finicity"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "finnhub-access-token",
"regex": "[\\w.-]{0,50}?(?:[fF][iI][nN][nN][hH][uU][bB])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{20})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"finnhub"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "flickr-access-token",
"regex": "[\\w.-]{0,50}?(?:[fF][lL][iI][cC][kK][rR])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"flickr"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "flutterwave-encryption-key",
"regex": "FLWSECK_TEST-[a-hA-H0-9]{12}",
"keywords": [
"flwseck_test"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "flutterwave-public-key",
"regex": "FLWPUBK_TEST-[a-hA-H0-9]{32}-[Xx]",
"keywords": [
"flwpubk_test"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "flutterwave-secret-key",
"regex": "FLWSECK_TEST-[a-hA-H0-9]{32}-[Xx]",
"keywords": [
"flwseck_test"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "flyio-access-token",
"regex": "\\b((?:fo1_[\\w-]{43}|fm1[ar]_[a-zA-Z0-9+\\/]{100,}={0,3}|fm2_[a-zA-Z0-9+\\/]{100,}={0,3}))(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"fo1_",
"fm1",
"fm2_"
],
"entropy": 4,
"secretGroup": 0,
"allow": []
},
{
"id": "frameio-api-token",
"regex": "fio-u-[a-zA-Z0-9\\-_=]{64}",
"keywords": [
"fio-u-"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "freshbooks-access-token",
"regex": "[\\w.-]{0,50}?(?:[fF][rR][eE][sS][hH][bB][oO][oO][kK][sS])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"freshbooks"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "gcp-api-key",
"regex": "\\b(AIza[\\w-]{35})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"aiza"
],
"entropy": 4,
"secretGroup": 0,
"allow": [
{
"target": "secret",
"regexes": [
"AI[z]aSyabcdefghijklmnopqrstuvwxyz1234567",
"AI[z]aSyAnLA7NfeLquW1tJFpx_eQCxoX-oo6YyIs",
"AI[z]aSyCkEhVjf3pduRDt6d1yKOMitrUEke8agEM",
"AI[z]aSyDMAScliyLx7F0NPDEJi1QmyCgHIAODrlU",
"AI[z]aSyD3asb-2pEZVqMkmL6M9N6nHZRR_znhrh0",
"AI[z]ayDNSXIbFmlXbIE6mCzDLQAqITYefhixbX4A",
"AI[z]aSyAdOS2zB6NCsk1pCdZ4-P6GBdi_UUPwX7c",
"AI[z]aSyASWm6HmTMdYWpgMnjRBjxcQ9CKctWmLd4",
"AI[z]aSyANUvH9H9BsUccjsu2pCmEkOPjjaXeDQgY",
"AI[z]aSyA5_iVawFQ8ABuTZNUdcwERLJv_a_p4wtM",
"AI[z]aSyA4UrcGxgwQFTfaI3no3t7Lt1sjmdnP5sQ",
"AI[z]aSyDSb51JiIcB6OJpwwMicseKRhhrOq1cS7g",
"AI[z]aSyBF2RrAIm4a0mO64EShQfqfd2AFnzAvvuU",
"AI[z]aSyBcE-OOIbhjyR83gm4r2MFCu4MJmprNXsw",
"AI[z]aSyB8qGxt4ec15vitgn44duC5ucxaOi4FmqE",
"AI[z]aSyA8vmApnrHNFE0bApF4hoZ11srVL_n0nvY"
],
"stopwords": []
}
]
},
{
"id": "generic-api-key",
"regex": "[\\w.-]{0,50}?(?:[aA][cC][cC][eE][sS][sS]|[aA][uU][tT][hH]|(?:[Aa]pi|API)|[cC][rR][eE][dD][eE][nN][tT][iI][aA][lL]|[cC][rR][eE][dD][sS]|[kK][eE][yY]|[pP][aA][sS][sS][wW](?:[oO][rR])?[dD]|[sS][eE][cC][rR][eE][tT]|[tT][oO][kK][eE][nN])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([\\w.=-]{10,150}|[a-zA-Z0-9][a-zA-Z0-9+/]{11,}={0,3})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"access",
"api",
"auth",
"key",
"credential",
"creds",
"passwd",
"password",
"secret",
"token"
],
"entropy": 3.5,
"secretGroup": 0,
"allow": [
{
"target": "secret",
"regexes": [
"^[a-zA-Z_.-]+$"
],
"stopwords": []
},
{
"target": "match",
"regexes": [
"(?:[aA][cC][cC][eE][sS][sS](?:[iI][bB][iI][lL][iI][tT][yY]|[oO][rR])|[aA][cC][cC][eE][sS][sS][_.-]?[iI][dD]|[rR][aA][nN][dD][oO][mM][_.-]?[aA][cC][cC][eE][sS][sS]|[aA][pP][iI][_.-]?(?:[iI][dD]|[nN][aA][mM][eE]|[vV][eE][rR][sS][iI][oO][nN])|[rR][aA][pP][iI][dD]|[cC][aA][pP][iI][tT][aA][lL]|[a-zA-Z0-9-]*?[aA][pP][iI][a-zA-Z0-9-]*?:[jJ][aA][rR]:|[aA][uU][tT][hH][oO][rR]|[Xx]-[Mm][Ss]-[Ee][xX][cC][hH][aA][nN][gG][eE]-[Oo][rR][gG][aA][nN][iI][zZ][aA][tT][iI][oO][nN]-[Aa][uU][tT][hH]|[Aa][uU][tT][hH][eE][nN][tT][iI][cC][aA][tT][iI][oO][nN]-[Rr][eE][sS][uU][lL][tT][sS]|(?:[cC][rR][eE][dD][eE][nN][tT][iI][aA][lL][sS]?[_.-]?[iI][dD]|[wW][iI][tT][hH][Cc][rR][eE][dD][eE][nN][tT][iI][aA][lL][sS])|(?:[bB][uU][cC][kK][eE][tT]|[fF][oO][rR][eE][iI][gG][nN]|[hH][oO][tT]|[iI][dD][xX]|[nN][aA][tT][uU][rR][aA][lL]|[pP][rR][iI][mM][aA][rR][yY]|[pP][uU][bB](?:[lL][iI][cC])?|[sS][cC][hH][eE][mM][aA]|[sS][eE][qQ][uU][eE][nN][cC][eE])[_.-]?[kK][eE][yY]|(?:[tT][uU][rR][kK][eE][yY])|[kK][eE][yY][_.-]?(?:[aA][lL][iI][aA][sS]|[bB][oO][aA][rR][dD]|[cC][oO][dD][eE]|[fF][rR][aA][mM][eE]|[iI][dD]|[lL][eE][nN][gG][tT][hH]|[mM][eE][sS][hH]|[nN][aA][mM][eE]|[pP][aA][iI][rR]|[pP][rR][eE][sS][sS](?:[eE][dD])?|[rR][iI][nN][gG]|[sS][eE][lL][eE][cC][tT][oO][rR]|[sS][iI][gG][nN][aA][tT][uU][rR][eE]|[sS][iI][zZ][eE]|[sS][tT][oO][nN][eE]|[sS][tT][oO][rR][eE][tT][yY][pP][eE]|[wW][oO][rR][dD]|[uU][pP]|[dD][oO][wW][nN]|[lL][eE][fF][tT]|[rR][iI][gG][hH][tT])|[kK][eE][yY][_.-]?[vV][aA][uU][lL][tT][_.-]?(?:[iI][dD]|[nN][aA][mM][eE])|[kK][eE][yY][Vv][aA][uU][lL][tT][Tt][oO][Ss][tT][oO][rR][eE][Ss][eE][cC][rR][eE][tT][sS]|[kK][eE][yY](?:[sS][tT][oO][rR][eE]|[tT][aA][bB])[_.-]?(?:[fF][iI][lL][eE]|[pP][aA][tT][hH])|[iI][sS][sS][uU][eE][rR][kK][eE][yY][hH][aA][sS][hH]|(?:[DdMm]onkey|[DM]ONKEY)|[kK][eE][yY][iI][nN][gG]|(?:[sS][eE][cC][rR][eE][tT])[_.-]?(?:[lL][eE][nN][gG][tT][hH]|[nN][aA][mM][eE]|[sS][iI][zZ][eE])|[Uu][sS][eE][rR][Ss][eE][cC][rR][eE][tT][sS][Ii][dD]|(?:[cC][sS][rR][fF])[_.-]?[tT][oO][kK][eE][nN]|(?:[iI][oO]\\.[jJ][sS][oO][nN][wW][eE][bB][tT][oO][kK][eE][nN][ \\t]?:[ \\t]?[\\w-]+)|(?:[aA][pP][iI]|[cC][rR][eE][dD][eE][nN][tT][iI][aA][lL][sS]|[tT][oO][kK][eE][nN])[_.-]?(?:[eE][nN][dD][pP][oO][iI][nN][tT]|[uU][rR][iIlL])|[pP][uU][bB][lL][iI][cC][_.-]?[tT][oO][kK][eE][nN]|(?:[kK][eE][yY]|[tT][oO][kK][eE][nN])[_.-]?[fF][iI][lL][eE]|(?:(?:[A-Z_]+=\\n[A-Z_]+=|[a-z_]+=\\n[a-z_]+=)(?:\\n|$))|(?:(?:[A-Z.]+=\\n[A-Z.]+=|[a-z.]+=\\n[a-z.]+=)(?:\\n|$)))"
],
"stopwords": [
"000000",
"6fe4476ee5a1832882e326b506d14126",
"_ec2_",
"aaaaaa",
"about",
"abstract",
"academy",
"acces",
"account",
"act-",
"act.",
"act_",
"action",
"active",
"actively",
"activity",
"adapter",
"add-",
"add-on",
"add.",
"add_",
"addon",
"addres",
"admin",
"adobe",
"advanced",
"adventure",
"agent",
"agile",
"air-",
"air.",
"air_",
"ajax",
"akka",
"alert",
"alfred",
"algorithm",
"all-",
"all.",
"all_",
"alloy",
"alpha",
"amazon",
"amqp",
"analysi",
"analytic",
"analyzer",
"android",
"angular",
"angularj",
"animate",
"animation",
"another",
"ansible",
"answer",
"ant-",
"ant.",
"ant_",
"any-",
"any.",
"any_",
"apache",
"app-",
"app.",
"app_",
"apple",
"arch",
"archive",
"archived",
"arduino",
"array",
"art-",
"art.",
"art_",
"article",
"asp-",
"asp.",
"asp_",
"asset",
"async",
"atom",
"attention",
"audio",
"audit",
"aura",
"auth",
"author",
"authorize",
"auto",
"automated",
"automatic",
"awesome",
"aws_",
"azure",
"back",
"backbone",
"backend",
"backup",
"bar-",
"bar.",
"bar_",
"base",
"based",
"bash",
"basic",
"batch",
"been",
"beer",
"behavior",
"being",
"benchmark",
"best",
"beta",
"better",
"big-",
"big.",
"big_",
"binary",
"binding",
"bit-",
"bit.",
"bit_",
"bitcoin",
"block",
"blog",
"board",
"book",
"bookmark",
"boost",
"boot",
"bootstrap",
"bosh",
"bot-",
"bot.",
"bot_",
"bower",
"box-",
"box.",
"box_",
"boxen",
"bracket",
"branch",
"bridge",
"browser",
"brunch",
"buffer",
"bug-",
"bug.",
"bug_",
"build",
"builder",
"building",
"buildout",
"buildpack",
"built",
"bundle",
"busines",
"but-",
"but.",
"but_",
"button",
"cache",
"caching",
"cakephp",
"calendar",
"call",
"camera",
"campfire",
"can-",
"can.",
"can_",
"canva",
"captcha",
"capture",
"card",
"carousel",
"case",
"cassandra",
"cat-",
"cat.",
"cat_",
"category",
"center",
"cento",
"challenge",
"change",
"changelog",
"channel",
"chart",
"chat",
"cheat",
"check",
"checker",
"chef",
"ches",
"chinese",
"chosen",
"chrome",
"ckeditor",
"clas",
"classe",
"classic",
"clean",
"cli-",
"cli.",
"cli_",
"client",
"clojure",
"clone",
"closure",
"cloud",
"club",
"cluster",
"cms-",
"cms_",
"coco",
"code",
"coding",
"coffee",
"color",
"combination",
"combo",
"command",
"commander",
"comment",
"commit",
"common",
"community",
"compas",
"compiler",
"complete",
"component",
"composer",
"computer",
"computing",
"con-",
"con.",
"con_",
"concept",
"conf",
"config",
"connect",
"connector",
"console",
"contact",
"container",
"contao",
"content",
"contest",
"context",
"control",
"convert",
"converter",
"conway'",
"cookbook",
"cookie",
"cool",
"copy",
"cordova",
"core",
"couchbase",
"couchdb",
"countdown",
"counter",
"course",
"craft",
"crawler",
"create",
"creating",
"creator",
"credential",
"crm-",
"crm.",
"crm_",
"cros",
"crud",
"csv-",
"csv.",
"csv_",
"cube",
"cucumber",
"cuda",
"current",
"currently",
"custom",
"daemon",
"dark",
"dart",
"dash",
"dashboard",
"data",
"database",
"date",
"day-",
"day.",
"day_",
"dead",
"debian",
"debug",
"debugger",
"deck",
"define",
"del-",
"del.",
"del_",
"delete",
"demo",
"deploy",
"design",
"designer",
"desktop",
"detection",
"detector",
"dev-",
"dev.",
"dev_",
"develop",
"developer",
"device",
"devise",
"diff",
"digital",
"directive",
"directory",
"discovery",
"display",
"django",
"dns-",
"dns_",
"doc-",
"doc.",
"doc_",
"docker",
"docpad",
"doctrine",
"document",
"doe-",
"doe.",
"doe_",
"dojo",
"dom-",
"dom.",
"dom_",
"domain",
"don't",
"done",
"dot-",
"dot.",
"dot_",
"dotfile",
"download",
"draft",
"drag",
"drill",
"drive",
"driven",
"driver",
"drop",
"dropbox",
"drupal",
"dsl-",
"dsl.",
"dsl_",
"dynamic",
"easy",
"ecdsa",
"eclipse",
"edit",
"editing",
"edition",
"editor",
"element",
"emac",
"email",
"embed",
"embedded",
"ember",
"emitter",
"emulator",
"encoding",
"endpoint",
"engine",
"english",
"enhanced",
"entity",
"entry",
"env_",
"episode",
"erlang",
"error",
"espresso",
"event",
"evented",
"example",
"exchange",
"exercise",
"experiment",
"expire",
"exploit",
"explorer",
"export",
"exporter",
"expres",
"ext-",
"ext.",
"ext_",
"extended",
"extension",
"external",
"extra",
"extractor",
"fabric",
"facebook",
"factory",
"fake",
"fast",
"feature",
"feed",
"fewfwef",
"ffmpeg",
"field",
"file",
"filter",
"find",
"finder",
"firefox",
"firmware",
"first",
"fish",
"fix-",
"fix_",
"flash",
"flask",
"flat",
"flex",
"flexible",
"flickr",
"flow",
"fluent",
"fluentd",
"fluid",
"folder",
"font",
"force",
"foreman",
"fork",
"form",
"format",
"formatter",
"forum",
"foundry",
"framework",
"free",
"friend",
"friendly",
"front-end",
"frontend",
"ftp-",
"ftp.",
"ftp_",
"fuel",
"full",
"fun-",
"fun.",
"fun_",
"func",
"future",
"gaia",
"gallery",
"game",
"gateway",
"gem-",
"gem.",
"gem_",
"gen-",
"gen.",
"gen_",
"general",
"generator",
"generic",
"genetic",
"get-",
"get.",
"get_",
"getenv",
"getting",
"ghost",
"gist",
"git-",
"git.",
"git_",
"github",
"gitignore",
"gitlab",
"glas",
"gmail",
"gnome",
"gnu-",
"gnu.",
"gnu_",
"goal",
"golang",
"gollum",
"good",
"google",
"gpu-",
"gpu.",
"gpu_",
"gradle",
"grail",
"graph",
"graphic",
"great",
"grid",
"groovy",
"group",
"grunt",
"guard",
"gui-",
"gui.",
"gui_",
"guide",
"guideline",
"gulp",
"gwt-",
"gwt.",
"gwt_",
"hack",
"hackathon",
"hacker",
"hacking",
"hadoop",
"haml",
"handler",
"hardware",
"has-",
"has_",
"hash",
"haskell",
"have",
"haxe",
"hello",
"help",
"helper",
"here",
"hero",
"heroku",
"high",
"hipchat",
"history",
"home",
"homebrew",
"homepage",
"hook",
"host",
"hosting",
"hot-",
"hot.",
"hot_",
"house",
"how-",
"how.",
"how_",
"html",
"http",
"hub-",
"hub.",
"hub_",
"hubot",
"human",
"icon",
"ide-",
"ide.",
"ide_",
"idea",
"identity",
"idiomatic",
"image",
"impact",
"import",
"important",
"importer",
"impres",
"index",
"infinite",
"info",
"injection",
"inline",
"input",
"inside",
"inspector",
"instagram",
"install",
"installer",
"instant",
"intellij",
"interface",
"internet",
"interview",
"into",
"intro",
"ionic",
"iphone",
"ipython",
"irc-",
"irc_",
"iso-",
"iso.",
"iso_",
"issue",
"jade",
"jasmine",
"java",
"jbos",
"jekyll",
"jenkin",
"jetbrains",
"job-",
"job.",
"job_",
"joomla",
"jpa-",
"jpa.",
"jpa_",
"jquery",
"json",
"just",
"kafka",
"karma",
"kata",
"kernel",
"keyboard",
"kindle",
"kit-",
"kit.",
"kit_",
"kitchen",
"knife",
"koan",
"kohana",
"lab-",
"lab.",
"lab_",
"lambda",
"lamp",
"language",
"laravel",
"last",
"latest",
"latex",
"launcher",
"layer",
"layout",
"lazy",
"ldap",
"leaflet",
"league",
"learn",
"learning",
"led-",
"led.",
"led_",
"leetcode",
"les-",
"les.",
"les_",
"level",
"leveldb",
"lib-",
"lib.",
"lib_",
"librarie",
"library",
"license",
"life",
"liferay",
"light",
"lightbox",
"like",
"line",
"link",
"linked",
"linkedin",
"linux",
"lisp",
"list",
"lite",
"little",
"load",
"loader",
"local",
"location",
"lock",
"log-",
"log.",
"log_",
"logger",
"logging",
"logic",
"login",
"logstash",
"longer",
"look",
"love",
"lua-",
"lua.",
"lua_",
"mac-",
"mac.",
"mac_",
"machine",
"made",
"magento",
"magic",
"mail",
"make",
"maker",
"making",
"man-",
"man.",
"man_",
"manage",
"manager",
"manifest",
"manual",
"map-",
"map.",
"map_",
"mapper",
"mapping",
"markdown",
"markup",
"master",
"math",
"matrix",
"maven",
"md5",
"mean",
"media",
"mediawiki",
"meetup",
"memcached",
"memory",
"menu",
"merchant",
"message",
"messaging",
"meta",
"metadata",
"meteor",
"method",
"metric",
"micro",
"middleman",
"migration",
"minecraft",
"miner",
"mini",
"minimal",
"mirror",
"mit-",
"mit.",
"mit_",
"mobile",
"mocha",
"mock",
"mod-",
"mod.",
"mod_",
"mode",
"model",
"modern",
"modular",
"module",
"modx",
"money",
"mongo",
"mongodb",
"mongoid",
"mongoose",
"monitor",
"monkey",
"more",
"motion",
"moved",
"movie",
"mozilla",
"mqtt",
"mule",
"multi",
"multiple",
"music",
"mustache",
"mvc-",
"mvc.",
"mvc_",
"mysql",
"nagio",
"name",
"native",
"need",
"neo-",
"neo.",
"neo_",
"nest",
"nested",
"net-",
"net.",
"net_",
"nette",
"network",
"new-",
"new.",
"new_",
"next",
"nginx",
"ninja",
"nlp-",
"nlp.",
"nlp_",
"node",
"nodej",
"nosql",
"not-",
"not.",
"not_",
"note",
"notebook",
"notepad",
"notice",
"notifier",
"now-",
"now.",
"now_",
"number",
"oauth",
"object",
"objective",
"obsolete",
"ocaml",
"octopres",
"official",
"old-",
"old.",
"old_",
"onboard",
"online",
"only",
"open",
"opencv",
"opengl",
"openshift",
"openwrt",
"option",
"oracle",
"org-",
"org.",
"org_",
"origin",
"original",
"orm-",
"orm.",
"orm_",
"osx-",
"osx_",
"our-",
"our.",
"our_",
"out-",
"out.",
"out_",
"output",
"over",
"overview",
"own-",
"own.",
"own_",
"pack",
"package",
"packet",
"page",
"panel",
"paper",
"paperclip",
"para",
"parallax",
"parallel",
"parse",
"parser",
"parsing",
"particle",
"party",
"password",
"patch",
"path",
"pattern",
"payment",
"paypal",
"pdf-",
"pdf.",
"pdf_",
"pebble",
"people",
"perl",
"personal",
"phalcon",
"phoenix",
"phone",
"phonegap",
"photo",
"php-",
"php.",
"php_",
"physic",
"picker",
"pipeline",
"platform",
"play",
"player",
"please",
"plu-",
"plu.",
"plu_",
"plug-in",
"plugin",
"plupload",
"png-",
"png.",
"png_",
"poker",
"polyfill",
"polymer",
"pool",
"pop-",
"pop.",
"pop_",
"popcorn",
"popup",
"port",
"portable",
"portal",
"portfolio",
"post",
"power",
"powered",
"powerful",
"prelude",
"pretty",
"preview",
"principle",
"print",
"pro-",
"pro.",
"pro_",
"problem",
"proc",
"product",
"profile",
"profiler",
"program",
"progres",
"project",
"protocol",
"prototype",
"provider",
"proxy",
"public",
"pull",
"puppet",
"pure",
"purpose",
"push",
"pusher",
"pyramid",
"python",
"quality",
"query",
"queue",
"quick",
"rabbitmq",
"rack",
"radio",
"rail",
"railscast",
"random",
"range",
"raspberry",
"rdf-",
"rdf.",
"rdf_",
"react",
"reactive",
"read",
"reader",
"readme",
"ready",
"real",
"real-time",
"reality",
"realtime",
"recipe",
"recorder",
"red-",
"red.",
"red_",
"reddit",
"redi",
"redmine",
"reference",
"refinery",
"refresh",
"registry",
"related",
"release",
"remote",
"rendering",
"repo",
"report",
"request",
"require",
"required",
"requirej",
"research",
"resource",
"response",
"resque",
"rest",
"restful",
"resume",
"reveal",
"reverse",
"review",
"riak",
"rich",
"right",
"ring",
"robot",
"role",
"room",
"router",
"routing",
"rpc-",
"rpc.",
"rpc_",
"rpg-",
"rpg.",
"rpg_",
"rspec",
"ruby-",
"ruby.",
"ruby_",
"rule",
"run-",
"run.",
"run_",
"runner",
"running",
"runtime",
"rust",
"rvm-",
"rvm.",
"rvm_",
"salt",
"sample",
"sandbox",
"sas-",
"sas.",
"sas_",
"sbt-",
"sbt.",
"sbt_",
"scala",
"scalable",
"scanner",
"schema",
"scheme",
"school",
"science",
"scraper",
"scratch",
"screen",
"script",
"scroll",
"scs-",
"scs.",
"scs_",
"sdk-",
"sdk.",
"sdk_",
"sdl-",
"sdl.",
"sdl_",
"search",
"secure",
"security",
"see-",
"see.",
"see_",
"seed",
"select",
"selector",
"selenium",
"semantic",
"sencha",
"send",
"sentiment",
"serie",
"server",
"service",
"session",
"set-",
"set.",
"set_",
"setting",
"setup",
"sha1",
"sha2",
"sha256",
"share",
"shared",
"sharing",
"sheet",
"shell",
"shield",
"shipping",
"shop",
"shopify",
"shortener",
"should",
"show",
"showcase",
"side",
"silex",
"simple",
"simulator",
"single",
"site",
"skeleton",
"sketch",
"skin",
"slack",
"slide",
"slider",
"slim",
"small",
"smart",
"smtp",
"snake",
"snapshot",
"snippet",
"soap",
"social",
"socket",
"software",
"solarized",
"solr",
"solution",
"solver",
"some",
"soon",
"source",
"space",
"spark",
"spatial",
"spec",
"sphinx",
"spine",
"spotify",
"spree",
"spring",
"sprite",
"sql-",
"sql.",
"sql_",
"sqlite",
"ssh-",
"ssh.",
"ssh_",
"stack",
"staging",
"standard",
"stanford",
"start",
"started",
"starter",
"startup",
"stat",
"statamic",
"state",
"static",
"statistic",
"statsd",
"statu",
"steam",
"step",
"still",
"stm-",
"stm.",
"stm_",
"storage",
"store",
"storm",
"story",
"strategy",
"stream",
"streaming",
"string",
"stripe",
"structure",
"studio",
"study",
"stuff",
"style",
"sublime",
"sugar",
"suite",
"summary",
"super",
"support",
"supported",
"svg-",
"svg.",
"svg_",
"svn-",
"svn.",
"svn_",
"swagger",
"swift",
"switch",
"switcher",
"symfony",
"symphony",
"sync",
"synopsi",
"syntax",
"system",
"tab-",
"tab.",
"tab_",
"table",
"tag-",
"tag.",
"tag_",
"talk",
"target",
"task",
"tcp-",
"tcp.",
"tcp_",
"tdd-",
"tdd.",
"tdd_",
"team",
"tech",
"template",
"term",
"terminal",
"testing",
"tetri",
"text",
"textmate",
"theme",
"theory",
"three",
"thrift",
"time",
"timeline",
"timer",
"tiny",
"tinymce",
"tip-",
"tip.",
"tip_",
"title",
"todo",
"todomvc",
"token",
"tool",
"toolbox",
"toolkit",
"top-",
"top.",
"top_",
"tornado",
"touch",
"tower",
"tracker",
"tracking",
"traffic",
"training",
"transfer",
"translate",
"transport",
"tree",
"trello",
"try-",
"try.",
"try_",
"tumblr",
"tut-",
"tut.",
"tut_",
"tutorial",
"tweet",
"twig",
"twitter",
"type",
"typo",
"ubuntu",
"uiview",
"ultimate",
"under",
"unit",
"unity",
"universal",
"unix",
"update",
"updated",
"upgrade",
"upload",
"uploader",
"uri-",
"uri.",
"uri_",
"url-",
"url.",
"url_",
"usage",
"usb-",
"usb.",
"usb_",
"use-",
"use.",
"use_",
"used",
"useful",
"user",
"using",
"util",
"utilitie",
"utility",
"vagrant",
"validator",
"value",
"variou",
"varnish",
"version",
"via-",
"via.",
"via_",
"video",
"view",
"viewer",
"vim-",
"vim.",
"vim_",
"vimrc",
"virtual",
"vision",
"visual",
"vpn",
"want",
"warning",
"watch",
"watcher",
"wave",
"way-",
"way.",
"way_",
"weather",
"web-",
"web_",
"webapp",
"webgl",
"webhook",
"webkit",
"webrtc",
"website",
"websocket",
"welcome",
"what",
"what'",
"when",
"where",
"which",
"why-",
"why.",
"why_",
"widget",
"wifi",
"wiki",
"win-",
"win.",
"win_",
"window",
"wip-",
"wip.",
"wip_",
"within",
"without",
"wizard",
"word",
"wordpres",
"work",
"worker",
"workflow",
"working",
"workshop",
"world",
"wrapper",
"write",
"writer",
"writing",
"written",
"www-",
"www.",
"www_",
"xamarin",
"xcode",
"xml-",
"xml.",
"xml_",
"xmpp",
"xxxxxx",
"yahoo",
"yaml",
"yandex",
"yeoman",
"yet-",
"yet.",
"yet_",
"yii-",
"yii.",
"yii_",
"youtube",
"yui-",
"yui.",
"yui_",
"zend",
"zero",
"zip-",
"zip.",
"zip_",
"zsh-",
"zsh.",
"zsh_"
]
},
{
"target": "line",
"regexes": [
"--mount=type=secret,",
"import[ \\t]+\\{[ \\t\\w,]+\\}[ \\t]+from[ \\t]+['\"][^'\"]+['\"]"
],
"stopwords": []
}
]
},
{
"id": "github-app-token",
"regex": "(?:ghu|ghs)_[0-9a-zA-Z]{36}",
"keywords": [
"ghu_",
"ghs_"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "github-fine-grained-pat",
"regex": "github_pat_\\w{82}",
"keywords": [
"github_pat_"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "github-oauth",
"regex": "gho_[0-9a-zA-Z]{36}",
"keywords": [
"gho_"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "github-pat",
"regex": "ghp_[0-9a-zA-Z]{36}",
"keywords": [
"ghp_"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "github-refresh-token",
"regex": "ghr_[0-9a-zA-Z]{36}",
"keywords": [
"ghr_"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "gitlab-cicd-job-token",
"regex": "glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}",
"keywords": [
"glcbt-"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "gitlab-deploy-token",
"regex": "gldt-[0-9a-zA-Z_\\-]{20}",
"keywords": [
"gldt-"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "gitlab-feature-flag-client-token",
"regex": "glffct-[0-9a-zA-Z_\\-]{20}",
"keywords": [
"glffct-"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "gitlab-feed-token",
"regex": "glft-[0-9a-zA-Z_\\-]{20}",
"keywords": [
"glft-"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "gitlab-incoming-mail-token",
"regex": "glimt-[0-9a-zA-Z_\\-]{25}",
"keywords": [
"glimt-"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "gitlab-kubernetes-agent-token",
"regex": "glagent-[0-9a-zA-Z_\\-]{50}",
"keywords": [
"glagent-"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "gitlab-oauth-app-secret",
"regex": "gloas-[0-9a-zA-Z_\\-]{64}",
"keywords": [
"gloas-"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "gitlab-pat",
"regex": "glpat-[\\w-]{20}",
"keywords": [
"glpat-"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "gitlab-pat-routable",
"regex": "\\bglpat-[0-9a-zA-Z_-]{27,300}\\.[0-9a-z]{2}[0-9a-z]{7}\\b",
"keywords": [
"glpat-"
],
"entropy": 4,
"secretGroup": 0,
"allow": []
},
{
"id": "gitlab-ptt",
"regex": "glptt-[0-9a-f]{40}",
"keywords": [
"glptt-"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "gitlab-rrt",
"regex": "GR1348941[\\w-]{20}",
"keywords": [
"gr1348941"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "gitlab-runner-authentication-token",
"regex": "glrt-[0-9a-zA-Z_\\-]{20}",
"keywords": [
"glrt-"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "gitlab-runner-authentication-token-routable",
"regex": "\\bglrt-t\\d_[0-9a-zA-Z_\\-]{27,300}\\.[0-9a-z]{2}[0-9a-z]{7}\\b",
"keywords": [
"glrt-"
],
"entropy": 4,
"secretGroup": 0,
"allow": []
},
{
"id": "gitlab-scim-token",
"regex": "glsoat-[0-9a-zA-Z_\\-]{20}",
"keywords": [
"glsoat-"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "gitlab-session-cookie",
"regex": "_gitlab_session=[0-9a-z]{32}",
"keywords": [
"_gitlab_session="
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "gitter-access-token",
"regex": "[\\w.-]{0,50}?(?:[gG][iI][tT][tT][eE][rR])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9_-]{40})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"gitter"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "gocardless-api-token",
"regex": "[\\w.-]{0,50}?(?:[gG][oO][cC][aA][rR][dD][lL][eE][sS][sS])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([lL][iI][vV][eE]_[a-zA-Z0-9\\-_=]{40})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"live_",
"gocardless"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "grafana-api-key",
"regex": "\\b([eE][yY][Jj][rR][Ii][jJ][oO][iI][A-Za-za-zA-Z0-9]{70,400}={0,3})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"eyjrijoi"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "grafana-cloud-api-token",
"regex": "\\b([gG][lL][cC]_[A-Za-za-zA-Z0-9+/]{32,400}={0,3})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"glc_"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "grafana-service-account-token",
"regex": "\\b([gG][lL][sS][aA]_[A-Za-za-zA-Z0-9]{32}_[A-Fa-fa-fA-F0-9]{8})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"glsa_"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "harness-api-key",
"regex": "(?:pat|sat)\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{20}",
"keywords": [
"pat.",
"sat."
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "hashicorp-tf-api-token",
"regex": "[a-zA-Z0-9]{14}\\.(?:atlasv1)\\.[a-zA-Z0-9\\-_=]{60,70}",
"keywords": [
"atlasv1"
],
"entropy": 3.5,
"secretGroup": 0,
"allow": []
},
{
"id": "heroku-api-key",
"regex": "[\\w.-]{0,50}?(?:[hH][eE][rR][oO][kK][uU])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"heroku"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "heroku-api-key-v2",
"regex": "\\b((HRKU-AA[0-9a-zA-Z_-]{58}))(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"hrku-aa"
],
"entropy": 4,
"secretGroup": 0,
"allow": []
},
{
"id": "hubspot-api-key",
"regex": "[\\w.-]{0,50}?(?:[hH][uU][bB][sS][pP][oO][tT])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"hubspot"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "huggingface-access-token",
"regex": "\\b(hf_(?:[a-zA-Z]{34}))(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"hf_"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "huggingface-organization-api-token",
"regex": "\\b(api_org_(?:[a-zA-Z]{34}))(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"api_org_"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "infracost-api-token",
"regex": "\\b(ico-[a-zA-Z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"ico-"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "intercom-api-key",
"regex": "[\\w.-]{0,50}?(?:[iI][nN][tT][eE][rR][cC][oO][mM])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9=_\\-]{60})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"intercom"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "intra42-client-secret",
"regex": "\\b(s-s4t2(?:ud|af)-[aAbBcCdDeEfF0123456789]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"intra",
"s-s4t2ud-",
"s-s4t2af-"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "jfrog-api-key",
"regex": "[\\w.-]{0,50}?(?:[jJ][fF][rR][oO][gG]|[aA][rR][tT][iI][fF][aA][cC][tT][oO][rR][yY]|[bB][iI][nN][tT][rR][aA][yY]|[xX][rR][aA][yY])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{73})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"jfrog",
"artifactory",
"bintray",
"xray"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "jfrog-identity-token",
"regex": "[\\w.-]{0,50}?(?:[jJ][fF][rR][oO][gG]|[aA][rR][tT][iI][fF][aA][cC][tT][oO][rR][yY]|[bB][iI][nN][tT][rR][aA][yY]|[xX][rR][aA][yY])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"jfrog",
"artifactory",
"bintray",
"xray"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "jwt",
"regex": "\\b(ey[a-zA-Z0-9]{17,}\\.ey[a-zA-Z0-9\\/\\\\_-]{17,}\\.(?:[a-zA-Z0-9\\/\\\\_-]{10,}={0,2})?)(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"ey"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "jwt-base64",
"regex": "\\bZXlK(?:(?<alg>aGJHY2lPaU)|(?<apu>aGNIVWlPaU)|(?<apv>aGNIWWlPaU)|(?<aud>aGRXUWlPaU)|(?<b64>aU5qUWlP)|(?<crit>amNtbDBJanBi)|(?<cty>amRIa2lPaU)|(?<epk>bGNHc2lPbn)|(?<enc>bGJtTWlPaU)|(?<jku>cWEzVWlPaU)|(?<jwk>cWQyc2lPb)|(?<iss>cGMzTWlPaU)|(?<iv>cGRpSTZJ)|(?<kid>cmFXUWlP)|(?<key_ops>clpYbGZiM0J6SWpwY)|(?<kty>cmRIa2lPaUp)|(?<nonce>dWIyNWpaU0k2)|(?<p2c>d01tTWlP)|(?<p2s>d01uTWlPaU)|(?<ppt>d2NIUWlPaU)|(?<sub>emRXSWlPaU)|(?<svt>emRuUWlP)|(?<tag>MFlXY2lPaU)|(?<typ>MGVYQWlPaUp)|(?<url>MWNtd2l)|(?<use>MWMyVWlPaUp)|(?<ver>MlpYSWlPaU)|(?<version>MlpYSnphVzl1SWpv)|(?<x>NElqb2)|(?<x5c>NE5XTWlP)|(?<x5t>NE5YUWlPaU)|(?<x5ts256>NE5YUWpVekkxTmlJNkl)|(?<x5u>NE5YVWlPaU)|(?<zip>NmFYQWlPaU))[a-zA-Z0-9\\/\\\\_+\\-\\r\\n]{40,}={0,2}",
"keywords": [
"zxlk"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "kraken-access-token",
"regex": "[\\w.-]{0,50}?(?:[kK][rR][aA][kK][eE][nN])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9\\/=_\\+\\-]{80,90})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"kraken"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "kucoin-access-token",
"regex": "[\\w.-]{0,50}?(?:[kK][uU][cC][oO][iI][nN])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-fA-F0-9]{24})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"kucoin"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "kucoin-secret-key",
"regex": "[\\w.-]{0,50}?(?:[kK][uU][cC][oO][iI][nN])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"kucoin"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "launchdarkly-access-token",
"regex": "[\\w.-]{0,50}?(?:[lL][aA][uU][nN][cC][hH][dD][aA][rR][kK][lL][yY])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9=_\\-]{40})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"launchdarkly"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "linear-api-key",
"regex": "lin_api_[a-zA-Z0-9]{40}",
"keywords": [
"lin_api_"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "linear-client-secret",
"regex": "[\\w.-]{0,50}?(?:[lL][iI][nN][eE][aA][rR])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-fA-F0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"linear"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "linkedin-client-id",
"regex": "[\\w.-]{0,50}?(?:[lL][iI][nN][kK][eE][dD][_-]?[iI][nN])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{14})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"linkedin",
"linked_in",
"linked-in"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "linkedin-client-secret",
"regex": "[\\w.-]{0,50}?(?:[lL][iI][nN][kK][eE][dD][_-]?[iI][nN])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{16})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"linkedin",
"linked_in",
"linked-in"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "lob-api-key",
"regex": "[\\w.-]{0,50}?(?:[lL][oO][bB])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(([lL][iI][vV][eE]|[tT][eE][sS][tT])_[a-fA-F0-9]{35})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"test_",
"live_"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "lob-pub-api-key",
"regex": "[\\w.-]{0,50}?(?:[lL][oO][bB])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(([tT][eE][sS][tT]|[lL][iI][vV][eE])_[pP][uU][bB]_[a-fA-F0-9]{31})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"test_pub",
"live_pub",
"_pub"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "looker-client-id",
"regex": "[\\w.-]{0,50}?(?:[lL][oO][oO][kK][eE][rR])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{20})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"looker"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "looker-client-secret",
"regex": "[\\w.-]{0,50}?(?:[lL][oO][oO][kK][eE][rR])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{24})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"looker"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "mailchimp-api-key",
"regex": "[\\w.-]{0,50}?(?:[Mm][aA][iI][lL][cC][hH][iI][mM][pP][Ss][Dd][Kk].[iI][nN][iI][tT][iI][aA][lL][iI][zZ][eE]|[mM][aA][iI][lL][cC][hH][iI][mM][pP])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-fA-F0-9]{32}-[uU][sS]\\d\\d)(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"mailchimp"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "mailgun-private-api-token",
"regex": "[\\w.-]{0,50}?(?:[mM][aA][iI][lL][gG][uU][nN])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([kK][eE][yY]-[a-fA-F0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"mailgun"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "mailgun-pub-key",
"regex": "[\\w.-]{0,50}?(?:[mM][aA][iI][lL][gG][uU][nN])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([pP][uU][bB][kK][eE][yY]-[a-fA-F0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"mailgun"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "mailgun-signing-key",
"regex": "[\\w.-]{0,50}?(?:[mM][aA][iI][lL][gG][uU][nN])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-hA-H0-9]{32}-[a-hA-H0-9]{8}-[a-hA-H0-9]{8})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"mailgun"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "mapbox-api-token",
"regex": "[\\w.-]{0,50}?(?:[mM][aA][pP][bB][oO][xX])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([pP][kK]\\.[a-zA-Z0-9]{60}\\.[a-zA-Z0-9]{22})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"mapbox"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "mattermost-access-token",
"regex": "[\\w.-]{0,50}?(?:[mM][aA][tT][tT][eE][rR][mM][oO][sS][tT])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{26})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"mattermost"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "maxmind-license-key",
"regex": "\\b([A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk)(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"_mmk"
],
"entropy": 4,
"secretGroup": 0,
"allow": []
},
{
"id": "messagebird-api-token",
"regex": "[\\w.-]{0,50}?(?:[mM][eE][sS][sS][aA][gG][eE][_-]?[bB][iI][rR][dD])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{25})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"messagebird",
"message-bird",
"message_bird"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "messagebird-client-id",
"regex": "[\\w.-]{0,50}?(?:[mM][eE][sS][sS][aA][gG][eE][_-]?[bB][iI][rR][dD])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"messagebird",
"message-bird",
"message_bird"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "microsoft-teams-webhook",
"regex": "https://[a-z0-9]+\\.webhook\\.office\\.com/webhookb2/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}/IncomingWebhook/[a-z0-9]{32}/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}",
"keywords": [
"webhook.office.com",
"webhookb2",
"incomingwebhook"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "netlify-access-token",
"regex": "[\\w.-]{0,50}?(?:[nN][eE][tT][lL][iI][fF][yY])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9=_\\-]{40,46})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"netlify"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "new-relic-browser-api-token",
"regex": "[\\w.-]{0,50}?(?:[nN][eE][wW]-[rR][eE][lL][iI][cC]|[nN][eE][wW][rR][eE][lL][iI][cC]|[nN][eE][wW]_[rR][eE][lL][iI][cC])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([Nn][Rr][Jj][Ss]-[a-fA-F0-9]{19})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"nrjs-"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "new-relic-insert-key",
"regex": "[\\w.-]{0,50}?(?:[nN][eE][wW]-[rR][eE][lL][iI][cC]|[nN][eE][wW][rR][eE][lL][iI][cC]|[nN][eE][wW]_[rR][eE][lL][iI][cC])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([Nn][Rr][Ii][Ii]-[a-zA-Z0-9-]{32})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"nrii-"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "new-relic-user-api-id",
"regex": "[\\w.-]{0,50}?(?:[nN][eE][wW]-[rR][eE][lL][iI][cC]|[nN][eE][wW][rR][eE][lL][iI][cC]|[nN][eE][wW]_[rR][eE][lL][iI][cC])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"new-relic",
"newrelic",
"new_relic"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "new-relic-user-api-key",
"regex": "[\\w.-]{0,50}?(?:[nN][eE][wW]-[rR][eE][lL][iI][cC]|[nN][eE][wW][rR][eE][lL][iI][cC]|[nN][eE][wW]_[rR][eE][lL][iI][cC])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([Nn][Rr][Aa][Kk]-[a-zA-Z0-9]{27})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"nrak"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "notion-api-token",
"regex": "\\b(ntn_[0-9]{11}[A-Za-z0-9]{32}[A-Za-z0-9]{3})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"ntn_"
],
"entropy": 4,
"secretGroup": 0,
"allow": []
},
{
"id": "npm-access-token",
"regex": "\\b([nN][pP][mM]_[a-zA-Z0-9]{36})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"npm_"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "nytimes-access-token",
"regex": "[\\w.-]{0,50}?(?:[nN][yY][tT][iI][mM][eE][sS]|[nN][eE][wW]-[yY][oO][rR][kK]-[tT][iI][mM][eE][sS],|[nN][eE][wW][yY][oO][rR][kK][tT][iI][mM][eE][sS])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9=_\\-]{32})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"nytimes",
"new-york-times",
"newyorktimes"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "octopus-deploy-api-key",
"regex": "\\b(API-[A-Z0-9]{26})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"api-"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "okta-access-token",
"regex": "[\\w.-]{0,50}?(?:[\\w.-]{0,50}?(?:(?:[Oo]kta|OKTA))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(00[\\w=\\-]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"okta"
],
"entropy": 4,
"secretGroup": 0,
"allow": []
},
{
"id": "openai-api-key",
"regex": "\\b(sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})\\b|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"t3blbkfj"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "openshift-user-token",
"regex": "\\b(sha256~[\\w-]{43})(?:[^\\w-]|$)",
"keywords": [
"sha256~"
],
"entropy": 3.5,
"secretGroup": 0,
"allow": []
},
{
"id": "perplexity-api-key",
"regex": "\\b(pplx-[a-zA-Z0-9]{48})(?:[\\x60'\"\\s;]|\\\\[nr]|$|\\b)",
"keywords": [
"pplx-"
],
"entropy": 4,
"secretGroup": 0,
"allow": []
},
{
"id": "plaid-api-token",
"regex": "[\\w.-]{0,50}?(?:[pP][lL][aA][iI][dD])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([aA][cC][cC][eE][sS][sS]-(?:[sS][aA][nN][dD][bB][oO][xX]|[dD][eE][vV][eE][lL][oO][pP][mM][eE][nN][tT]|[pP][rR][oO][dD][uU][cC][tT][iI][oO][nN])-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"plaid"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "plaid-client-id",
"regex": "[\\w.-]{0,50}?(?:[pP][lL][aA][iI][dD])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{24})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"plaid"
],
"entropy": 3.5,
"secretGroup": 0,
"allow": []
},
{
"id": "plaid-secret-key",
"regex": "[\\w.-]{0,50}?(?:[pP][lL][aA][iI][dD])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{30})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"plaid"
],
"entropy": 3.5,
"secretGroup": 0,
"allow": []
},
{
"id": "planetscale-api-token",
"regex": "\\b(pscale_tkn_[\\w=\\.-]{32,64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"pscale_tkn_"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "planetscale-oauth-token",
"regex": "\\b(pscale_oauth_[\\w=\\.-]{32,64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"pscale_oauth_"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "planetscale-password",
"regex": "\\b([pP][sS][cC][aA][lL][eE]_[pP][wW]_[\\w=\\.-]{32,64})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"pscale_pw_"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "postman-api-token",
"regex": "\\b(PMAK-[a-fA-F0-9]{24}\\-[a-fA-F0-9]{34})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"pmak-"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "prefect-api-token",
"regex": "\\b(pnu_[a-zA-Z0-9]{36})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"pnu_"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "private-key",
"regex": "-----[Bb][Ee][Gg][Ii][Nn][ A-Za-z0-9_-]{0,100}[Pp][Rr][Ii][Vv][Aa][Tt][Ee] [Kk][Ee][Yy](?: [Bb][Ll][Oo][Cc][Kk])?-----[\\s\\S-]{64,}?[Kk][Ee][Yy](?: [Bb][Ll][Oo][Cc][Kk])?-----",
"keywords": [
"-----begin"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "privateai-api-token",
"regex": "[\\w.-]{0,50}?(?:[\\w.-]{0,50}?(?:[pP][rR][iI][vV][aA][tT][eE][_-]?[aA][iI])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"privateai",
"private_ai",
"private-ai"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "pulumi-api-token",
"regex": "\\b(pul-[a-f0-9]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"pul-"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "pypi-upload-token",
"regex": "pypi-AgEIcHlwaS5vcmc[\\w-]{50,1000}",
"keywords": [
"pypi-ageichlwas5vcmc"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "rapidapi-access-token",
"regex": "[\\w.-]{0,50}?(?:[rR][aA][pP][iI][dD][aA][pP][iI])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9_-]{50})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"rapidapi"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "readme-api-token",
"regex": "\\b(rdme_[a-z0-9]{70})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"rdme_"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "rubygems-api-token",
"regex": "\\b(rubygems_[a-f0-9]{48})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"rubygems_"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "scalingo-api-token",
"regex": "\\b(tk-us-[\\w-]{48})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"tk-us-"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "sendbird-access-id",
"regex": "[\\w.-]{0,50}?(?:[sS][eE][nN][dD][bB][iI][rR][dD])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"sendbird"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "sendbird-access-token",
"regex": "[\\w.-]{0,50}?(?:[sS][eE][nN][dD][bB][iI][rR][dD])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-fA-F0-9]{40})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"sendbird"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "sendgrid-api-token",
"regex": "\\b(SG\\.[a-zA-Z0-9=_\\-\\.]{66})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"sg."
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "sendinblue-api-token",
"regex": "\\b(xkeysib-[a-f0-9]{64}\\-[a-zA-Z0-9]{16})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"xkeysib-"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "sentry-access-token",
"regex": "[\\w.-]{0,50}?(?:[sS][eE][nN][tT][rR][yY])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-fA-F0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"sentry"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "sentry-org-token",
"regex": "\\bsntrys_eyJpYXQiO[a-zA-Z0-9+/]{10,200}(?:LCJyZWdpb25fdXJs|InJlZ2lvbl91cmwi|cmVnaW9uX3VybCI6)[a-zA-Z0-9+/]{10,200}={0,2}_[a-zA-Z0-9+/]{43}(?:[^a-zA-Z0-9+/]|$)",
"keywords": [
"sntrys_eyjpyxqio"
],
"entropy": 4.5,
"secretGroup": 0,
"allow": []
},
{
"id": "sentry-user-token",
"regex": "\\b(sntryu_[a-f0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"sntryu_"
],
"entropy": 3.5,
"secretGroup": 0,
"allow": []
},
{
"id": "settlemint-application-access-token",
"regex": "\\b(sm_aat_[a-zA-Z0-9]{16})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"sm_aat"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "settlemint-personal-access-token",
"regex": "\\b(sm_pat_[a-zA-Z0-9]{16})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"sm_pat"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "settlemint-service-access-token",
"regex": "\\b(sm_sat_[a-zA-Z0-9]{16})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"sm_sat"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "shippo-api-token",
"regex": "\\b(shippo_(?:live|test)_[a-fA-F0-9]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"shippo_"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "shopify-access-token",
"regex": "shpat_[a-fA-F0-9]{32}",
"keywords": [
"shpat_"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "shopify-custom-access-token",
"regex": "shpca_[a-fA-F0-9]{32}",
"keywords": [
"shpca_"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "shopify-private-app-access-token",
"regex": "shppa_[a-fA-F0-9]{32}",
"keywords": [
"shppa_"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "shopify-shared-secret",
"regex": "shpss_[a-fA-F0-9]{32}",
"keywords": [
"shpss_"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "sidekiq-secret",
"regex": "[\\w.-]{0,50}?(?:[Bb][Uu][Nn][Dd][Ll][Ee]_[Ee][Nn][Tt][Ee][Rr][Pp][Rr][Ii][Ss][Ee]__[Cc][Oo][Nn][Tt][Rr][Ii][Bb][Ss][Yy][Ss]__[Cc][Oo][Mm]|[Bb][Uu][Nn][Dd][Ll][Ee]_[Gg][Ee][Mm][Ss]__[Cc][Oo][Nn][Tt][Rr][Ii][Bb][Ss][Yy][Ss]__[Cc][Oo][Mm])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-fA-F0-9]{8}:[a-fA-F0-9]{8})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"bundle_enterprise__contribsys__com",
"bundle_gems__contribsys__com"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "sidekiq-sensitive-url",
"regex": "\\b[hH][tT][tT][pP][sS]?://([a-fA-F0-9]{8}:[a-fA-F0-9]{8})@(?:[gG][eE][mM][sS].[cC][oO][nN][tT][rR][iI][bB][sS][yY][sS].[cC][oO][mM]|[eE][nN][tT][eE][rR][pP][rR][iI][sS][eE].[cC][oO][nN][tT][rR][iI][bB][sS][yY][sS].[cC][oO][mM])(?:[\\/|\\#|\\?|:]|$)",
"keywords": [
"gems.contribsys.com",
"enterprise.contribsys.com"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "slack-app-token",
"regex": "[xX][aA][pP][pP]-\\d-[A-Za-z0-9]+-\\d+-[a-zA-Z0-9]+",
"keywords": [
"xapp"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "slack-bot-token",
"regex": "xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
"keywords": [
"xoxb"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "slack-config-access-token",
"regex": "[xX][oO][xX][eE].[xX][oO][xX][bBpP]-\\d-[A-Za-z0-9]{163,166}",
"keywords": [
"xoxe.xoxb-",
"xoxe.xoxp-"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "slack-config-refresh-token",
"regex": "[xX][oO][xX][eE]-\\d-[A-Za-z0-9]{146}",
"keywords": [
"xoxe-"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "slack-legacy-bot-token",
"regex": "xoxb-[0-9]{8,14}-[a-zA-Z0-9]{18,26}",
"keywords": [
"xoxb"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "slack-legacy-token",
"regex": "xox[os]-\\d+-\\d+-\\d+-[a-fA-F\\d]+",
"keywords": [
"xoxo",
"xoxs"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "slack-legacy-workspace-token",
"regex": "xox[ar]-(?:\\d-)?[0-9a-zA-Z]{8,48}",
"keywords": [
"xoxa",
"xoxr"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "slack-user-token",
"regex": "xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}",
"keywords": [
"xoxp-",
"xoxe-"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "slack-webhook-url",
"regex": "(?:https?://)?hooks.slack.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}",
"keywords": [
"hooks.slack.com"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "snyk-api-token",
"regex": "[\\w.-]{0,50}?(?:[sS][nN][yY][kK][_.-]?(?:(?:[aA][pP][iI]|[oO][aA][uU][tT][hH])[_.-]?)?(?:[kK][eE][yY]|[tT][oO][kK][eE][nN]))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"snyk"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "sonar-api-token",
"regex": "[\\w.-]{0,50}?(?:[sS][oO][nN][aA][rR][_.-]?([lL][oO][gG][iI][nN]|[tT][oO][kK][eE][nN]))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}((?:[sS][qQ][uU]_|[sS][qQ][pP]_|[sS][qQ][aA]_)?[a-zA-Z0-9=_\\-]{40})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"sonar"
],
"entropy": 0,
"secretGroup": 2,
"allow": []
},
{
"id": "sourcegraph-access-token",
"regex": "\\b(\\b([sS][gG][pP]_(?:[a-fA-FA-Fa-f0-9]{16}|[lL][oO][cC][aA][lL])_[a-fA-FA-Fa-f0-9]{40}|[sS][gG][pP]_[a-fA-FA-Fa-f0-9]{40}|[a-fA-FA-Fa-f0-9]{40})\\b)(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"sgp_",
"sourcegraph"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "square-access-token",
"regex": "\\b((?:EAAA|sq0atp-)[\\w-]{22,60})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"sq0atp-",
"eaaa"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "squarespace-access-token",
"regex": "[\\w.-]{0,50}?(?:[sS][qQ][uU][aA][rR][eE][sS][pP][aA][cC][eE])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"squarespace"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "stripe-access-token",
"regex": "\\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"sk_test",
"sk_live",
"sk_prod",
"rk_test",
"rk_live",
"rk_prod"
],
"entropy": 2,
"secretGroup": 0,
"allow": []
},
{
"id": "sumologic-access-id",
"regex": "[\\w.-]{0,50}?(?:[\\w.-]{0,50}?(?:(?:[Ss]umo|SUMO))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(su[a-zA-Z0-9]{12})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"sumo"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "sumologic-access-token",
"regex": "[\\w.-]{0,50}?(?:(?:[Ss]umo|SUMO))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"sumo"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "telegram-bot-api-token",
"regex": "[\\w.-]{0,50}?(?:[tT][eE][lL][eE][gG][rR])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9]{5,16}:(?:A)[a-zA-Z0-9_\\-]{34})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"telegr"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "travisci-access-token",
"regex": "[\\w.-]{0,50}?(?:[tT][rR][aA][vV][iI][sS])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{22})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"travis"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "twilio-api-key",
"regex": "SK[0-9a-fA-F]{32}",
"keywords": [
"sk"
],
"entropy": 3,
"secretGroup": 0,
"allow": []
},
{
"id": "twitch-api-token",
"regex": "[\\w.-]{0,50}?(?:[tT][wW][iI][tT][cC][hH])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{30})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"twitch"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "twitter-access-secret",
"regex": "[\\w.-]{0,50}?(?:[tT][wW][iI][tT][tT][eE][rR])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{45})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"twitter"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "twitter-access-token",
"regex": "[\\w.-]{0,50}?(?:[tT][wW][iI][tT][tT][eE][rR])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9]{15,25}-[a-zA-ZA-Za-z0-9]{20,40})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"twitter"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "twitter-api-key",
"regex": "[\\w.-]{0,50}?(?:[tT][wW][iI][tT][tT][eE][rR])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{25})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"twitter"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "twitter-api-secret",
"regex": "[\\w.-]{0,50}?(?:[tT][wW][iI][tT][tT][eE][rR])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{50})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"twitter"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "twitter-bearer-token",
"regex": "[\\w.-]{0,50}?(?:[tT][wW][iI][tT][tT][eE][rR])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([Aa]{22}[a-zA-ZA-Za-z0-9%]{80,100})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"twitter"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "typeform-api-token",
"regex": "[\\w.-]{0,50}?(?:[tT][yY][pP][eE][fF][oO][rR][mM])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([tT][fF][pP]_[a-zA-Z0-9\\-_\\.=]{59})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"tfp_"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "vault-batch-token",
"regex": "\\b(hvb\\.[\\w-]{138,300})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"hvb."
],
"entropy": 4,
"secretGroup": 0,
"allow": []
},
{
"id": "vault-service-token",
"regex": "\\b((?:hvs\\.[\\w-]{90,120}|s\\.(?:[a-zA-Z0-9]{24})))(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
"keywords": [
"hvs.",
"s."
],
"entropy": 3.5,
"secretGroup": 0,
"allow": [
{
"target": "secret",
"regexes": [
"s\\.[A-Za-z]{24}"
],
"stopwords": []
}
]
},
{
"id": "yandex-access-token",
"regex": "[\\w.-]{0,50}?(?:[yY][aA][nN][dD][eE][xX])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([tT]1\\.[A-Za-z0-9a-zA-Z_-]+[=]{0,2}\\.[A-Za-z0-9a-zA-Z_-]{86}[=]{0,2})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"yandex"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "yandex-api-key",
"regex": "[\\w.-]{0,50}?(?:[yY][aA][nN][dD][eE][xX])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([Aa][Qq][Vv][Nn][A-Za-za-zA-Z0-9_\\-]{35,38})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"yandex"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "yandex-aws-access-token",
"regex": "[\\w.-]{0,50}?(?:[yY][aA][nN][dD][eE][xX])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([Yy][Cc][a-zA-ZA-Za-z0-9_\\-]{38})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"yandex"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
},
{
"id": "zendesk-secret-key",
"regex": "[\\w.-]{0,50}?(?:[zZ][eE][nN][dD][eE][sS][kK])(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{40})(?:[\\x60'\"\\s;]|\\\\[nNrR]|$)",
"keywords": [
"zendesk"
],
"entropy": 0,
"secretGroup": 0,
"allow": []
}
]

export const GITLEAKS_GLOBAL_REGEXES: string[] = ["^[tT][rR][uU][eE]|[fF][aA][lL][sS][eE]|[nN][uU][lL][lL]$", "^(?:[aA]+|[bB]+|[cC]+|[dD]+|[eE]+|[fF]+|[gG]+|[hH]+|[iI]+|[jJ]+|[kK]+|[lL]+|[mM]+|[nN]+|[oO]+|[pP]+|[qQ]+|[rR]+|[sS]+|[tT]+|[uU]+|[vV]+|[wW]+|[xX]+|[yY]+|[zZ]+|\\*+|\\.+)$", "^\\$(?:\\d+|\\{\\d+\\})$", "^\\$(?:[A-Z_]+|[a-z_]+)$", "^\\$\\{(?:[A-Z_]+|[a-z_]+)\\}$", "^\\{\\{[ \\t]*[\\w ().|]+[ \\t]*\\}\\}$", "^\\$\\{\\{[ \\t]*(?:(?:env|github|secrets|vars)(?:\\.[A-Za-z]\\w+)+[\\w \"'&./=|]*)[ \\t]*\\}\\}$", "^%(?:[A-Z_]+|[a-z_]+)%$", "^%[+\\-# 0]?[bcdeEfFgGoOpqstTUvxX]$", "^\\{\\d{0,2}\\}$", "^@(?:[A-Z_]+|[a-z_]+)@$", "^/Users/[a-zA-Z0-9]+/[\\w .-/]+$", "^/(?:bin|etc|home|opt|tmp|usr|var)/[\\w ./-]+$"]

export const GITLEAKS_GLOBAL_STOPWORDS: string[] = ["014df517-39d1-4453-b7b3-9930c563627c", "abcdefghijklmnopqrstuvwxyz"]
