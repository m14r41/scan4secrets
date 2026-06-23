import React from 'react';
import clsx from 'clsx';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';
import HomepageFeatures from '@site/src/components/HomepageFeatures';
import styles from './index.module.css';

function Hero(): React.ReactElement {
  const {siteConfig} = useDocusaurusContext();
  return (
    <header className={clsx(styles.hero)}>
      <div className={styles.heroGlow} aria-hidden="true" />
      <div className="container">
        <div className={styles.heroBadge}>v2 &nbsp;·&nbsp; 170+ rules &nbsp;·&nbsp; live verification</div>
        <h1 className={styles.heroTitle}>
          Find <span className={styles.accent}>leaked secrets</span> across code, web apps, and CI.
        </h1>
        <p className={styles.heroSub}>{siteConfig.tagline}</p>
        <div className={styles.heroCtaRow}>
          <Link className={clsx('button button--primary button--lg', styles.ctaPrimary)} to="/docs/getting-started">
            Get started
          </Link>
          <Link className={clsx('button button--secondary button--lg', styles.ctaSecondary)} to="/docs/intro">
            Read the docs
          </Link>
          <Link
            className={clsx('button button--lg', styles.ctaGhost)}
            href="https://github.com/m14r41/scan4secrets"
            target="_blank"
            rel="noopener noreferrer"
          >
            Star on GitHub
          </Link>
        </div>

        <div className={styles.installBox}>
          <div className={styles.installTabs}>
            <span className={styles.installTab}>pipx</span>
            <span className={styles.installTabAlt}>docker</span>
            <span className={styles.installTabAlt}>release</span>
          </div>
          <pre className={styles.installCmd}>
            <code>{`# install with pipx (recommended)
pipx install git+https://github.com/m14r41/scan4secrets

# OR run via Docker
docker run --rm -v $(pwd):/scan ghcr.io/m14r41/scan4secrets:latest --path /scan

# OR grab a prebuilt binary
# Windows64 and Linux amd64: /docs/downloads`}</code>
          </pre>
        </div>
      </div>
    </header>
  );
}

type Row = readonly [string, boolean, boolean, boolean, boolean];

const COMPARE_ROWS: readonly Row[] = [
  ['SAST secret detection', true, true, true, true],
  ['DAST live web crawl', false, false, false, true],
  ['JS source-map parsing', false, false, false, true],
  ['JS endpoint extraction', false, false, false, true],
  ['HTTP header secret scan', false, false, false, true],
  ['Live token verification', false, true, false, true],
  ['SARIF output', true, false, false, true],
  ['Excel, PDF, HTML reports', false, false, false, true],
  ['Authenticated DAST (cookie, header, proxy)', false, false, false, true],
] as const;

function Cell({yes}: {yes: boolean}): React.ReactElement {
  return yes ? (
    <td className={styles.yesCell}>
      <span className={styles.pillYes}>Yes</span>
    </td>
  ) : (
    <td className={styles.noCell}>
      <span className={styles.pillNo}>No</span>
    </td>
  );
}

function ComparisonTable(): React.ReactElement {
  return (
    <section className={styles.compareSection}>
      <div className="container">
        <h2 className={styles.sectionTitle}>How it compares</h2>
        <p className={styles.sectionSub}>
          scan4secrets is meant to sit alongside gitleaks, not replace it. Use both.
        </p>
        <div className={styles.tableWrap}>
          <table className={styles.compareTable}>
            <thead>
              <tr>
                <th className={styles.thLabel}>Capability</th>
                <th>gitleaks</th>
                <th>trufflehog</th>
                <th>detect-secrets</th>
                <th className={styles.us}>scan4secrets</th>
              </tr>
            </thead>
            <tbody>
              {COMPARE_ROWS.map(([label, ...vals], i) => (
                <tr key={i}>
                  <td className={styles.tdLabel}>{label}</td>
                  {vals.map((v, j) => (
                    <Cell key={j} yes={v} />
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}

function StatsBand(): React.ReactElement {
  const stats = [
    {n: '170+', l: 'Detection rules'},
    {n: '1279', l: 'DAST wordlist paths'},
    {n: '7', l: 'Report formats'},
    {n: '20+', l: 'Live vendor probes'},
  ];
  return (
    <section className={styles.statsBand}>
      <div className="container">
        <div className={styles.statsGrid}>
          {stats.map((s) => (
            <div key={s.l} className={styles.stat}>
              <div className={styles.statN}>{s.n}</div>
              <div className={styles.statL}>{s.l}</div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function CTA(): React.ReactElement {
  return (
    <section className={styles.ctaSection}>
      <div className="container">
        <h2 className={styles.sectionTitle}>Ready to scan?</h2>
        <p className={styles.sectionSub}>
          One command. SAST and DAST. SARIF for code-scanning, PDF for clients.
        </p>
        <div className={styles.heroCtaRow}>
          <Link className={clsx('button button--primary button--lg', styles.ctaPrimary)} to="/docs/getting-started">
            Get started
          </Link>
          <Link className={clsx('button button--secondary button--lg', styles.ctaSecondary)} to="/docs/downloads">
            Download binary
          </Link>
        </div>
      </div>
    </section>
  );
}

export default function Home(): React.ReactElement {
  const {siteConfig} = useDocusaurusContext();
  return (
    <Layout title="Home" description={siteConfig.tagline}>
      <Hero />
      <main>
        <StatsBand />
        <HomepageFeatures />
        <ComparisonTable />
        <CTA />
      </main>
    </Layout>
  );
}
