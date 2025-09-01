# Splunk trusseljakt (Botsv1)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Lab Only](https://img.shields.io/badge/Scope-Lab%20Only-blue)

**Kort fortalt:** Jeg undersøker *Botsv1* i Splunk: kartlegger indekser og protokoller, avdekker HTTP-angrep mot `ireallynotbatman.com`, identifiserer servere (IIS/porter), og viser POST-skjemaer med `username`/`passwd`. Alt i et fiktivt, isolert labmiljø.

## Mål
- Kartlegge tilgjengelige **indekser** og **dominerende protokoller**
- Finne **angrep/aktivitet** mot `ireallynotbatman.com`
- Identifisere **serverfingeravtrykk** (IP/port/Server-header)
- Avdekke **POST-skjemaer** med `username` og `passwd`

## Miljø og datakilder
- Splunk (Search & Reporting), datasett **Botsv1** (`stream:*`, web-logger, **suricata**)
- Repoet inneholder **kun dokumentasjon og skjermbilder** (ikke rådata)

## 1) Indekser i miljøet

**SPL**
```spl
| eventcount summarize=false index=*
| dedup index
| fields index
```
<img width="436" height="220" alt="01-index-list" src="https://github.com/user-attachments/assets/3889b6d9-374f-4f09-b3c7-28c7477321c1" />

---

## 2) Dominerende protokoller

**SPL (tabell)**
```spl
index="botsv1" earliest=0 sourcetype="stream:tcp"
| search app IN ("http","msrpc","ssl","smb","tcp","rdp","krb5","ldap","dcerpc",
                 "svcctl","ssh","cotp","ocsp","netbios","dns","https")
| stats count by app
| sort -count
| table app, count
```
<img width="1074" height="596" alt="02-stream-app-counts" src="https://github.com/user-attachments/assets/62d4249d-22ad-4b82-b321-91e0aaa3b8b7" />


**SPL (Topp 4 vist i pie-chart)**
```spl
index="botsv1" earliest=0 sourcetype="stream:tcp"
| search app!="unknown"
| stats count by app
| sort -count
| head 4
```
<img width="505" height="223" alt="03-stream-top4-pie" src="https://github.com/user-attachments/assets/11ce92be-8942-4817-9c3f-7e52e36409cd" />

---

## 3) HTTP-angrep mot "ireallynotbatman.com"

**SPL**
```spl
index="botsv1" earliest=0 host="ireallynotbatman.com"
| stats count by srcip, service, attack
| sort -count
```
<img width="445" height="293" alt="04-attacks-by-src-service" src="https://github.com/user-attachments/assets/f342415d-6bb2-4aac-a7f5-f30ca9492bc7" />

---

## 4) Serverfingeravtrykk (IP/port/Server)

**SPL**
```spl
index="botsv1" earliest=0 "ireallynotbatman.com"
| stats values(destip) as IP, values(dest_port) as Port, values(server) as Server
| table IP, Port, Server
```
<img width="552" height="149" alt="05-host-servers-table" src="https://github.com/user-attachments/assets/c6b20258-d4ec-4290-8d4f-262348ce1724" />

---

## 5) IDS-funn (Suricata — XSS)

**SPL**
```spl
index="botsv1" earliest=0 sourcetype="suricata" "cross site scripting"
```
<img width="439" height="225" alt="06-suricata-xss-event" src="https://github.com/user-attachments/assets/703a2e79-4517-43eb-8b23-8bfe43e2bbcb" />

---

## 6) Rå HTTP-innhold fra IIS

**SPL**
```spl
index="botsv1" earliest=0 dest_ip="192.168.250.49" dest_port=80 dest_content=*
```
<img width="507" height="291" alt="07-iis-raw-http" src="https://github.com/user-attachments/assets/62713f8a-513d-44cd-9d96-3881902d59f6" />

---

## 7) POST-skjemaer med username/passwd

**Grovt søk (utelukk skannere som Acunetix)**
```spl
index="botsv1" earliest=0 http_method=POST host="ireallynotbatman.com"
| search NOT Acunetix "username=" "passwd="
| top limit=20 form_data
```
<img width="606" height="144" alt="08-post-forms-top" src="https://github.com/user-attachments/assets/71a2ec49-2710-4562-b9df-c08a7d0ed68b" />


**Strammere match (regex-eksempel)**
```spl
index="botsv1" earliest=0 http_method=POST host="ireallynotbatman.com" "username=" "passwd="
| where match(form_data, "passwd=[^&]{8,}")
| top limit=20 form_data
```
<img width="598" height="133" alt="09-post-forms-regex" src="https://github.com/user-attachments/assets/34d128a6-78c5-4272-9d27-311868213546" />

---

> **Etikk**: Alt er utført i et rent labmiljø.

**Læringspoeng**

- Start bredt (indekser/protokoller) → zoom inn (vertsangrep, POST-mønstre)

- Kombiner kilder: stream:* (protokoller), Suricata (IDS), web-logger (innhold)

- Filtrér støy (skannere) før telling/visualisering

**Defensive notater**

- Varsle på mønstre i POST (felter username/passwd) og uvanlige rater

- Dashboards: topp angrep pr. IP/kilde, serverfingeravtrykk pr. host

- Berik web-logger: server, user_agent, referer for raskere triage



























