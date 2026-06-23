import React from 'react';
import clsx from 'clsx';
import styles from './styles.module.css';

type Feature = {title: string; body: string; icon: React.ReactElement};

const Features: Feature[] = [
  {
    title: 'DAST live web crawl',
    body: 'Crawls staging or prod, parses JS source-maps, extracts endpoints, scans response headers. Catches secrets no SAST will ever see.',
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
    ),
  },
  {
    title: 'Live verification',
    body: 'Twenty plus vendor probes confirm a token is live in one HTTP call. Hypothesis becomes evidence before you write the report.',
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
    ),
  },
  {
    title: '170+ rules out of the box',
    body: 'Cloud, payments, AI/ML, messaging, monitoring, databases, JWT, PEM keys. Add your own with a YAML block. No code change.',
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
    ),
  },
  {
    title: 'CI native reporting',
    body: 'SARIF for GitHub code-scanning, JSONL for SOAR, Excel and PDF and HTML for client reports. Exit-code gate on severity.',
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg>
    ),
  },
  {
    title: 'Authenticated DAST',
    body: 'Cookies, headers, Burp or ZAP proxy. Scan behind login with the same engine and rules you use everywhere else.',
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
    ),
  },
  {
    title: 'Fast and safe',
    body: 'Aho-Corasick keyword pre-filter, binary skip, line-length cap, scope honoring, hard caps on URLs and depth. No accidental DoS.',
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
    ),
  },
];

export default function HomepageFeatures(): React.ReactElement {
  return (
    <section className={styles.features}>
      <div className="container">
        <h2 className={styles.title}>What makes it different</h2>
        <p className={styles.subtitle}>Six things gitleaks, trufflehog, and detect-secrets cannot do.</p>
        <div className={styles.grid}>
          {Features.map((f, i) => (
            <div key={i} className={clsx('card', styles.card)}>
              <div className={styles.icon}>{f.icon}</div>
              <h3 className={styles.cardTitle}>{f.title}</h3>
              <p className={styles.cardBody}>{f.body}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
