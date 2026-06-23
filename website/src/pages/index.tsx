import React, {useState} from 'react';
import clsx from 'clsx';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';
import HomepageFeatures from '@site/src/components/HomepageFeatures';
import styles from './index.module.css';

type InstallTab = 'pipx' | 'docker' | 'release';

const INSTALL_COMMANDS: Record<InstallTab, string> = {
  pipx: `# Install with pipx (recommended, isolated env, single binary on PATH)
pipx install scan4secrets

# Verify
scan4secrets --version

# Run your first scan
scan4secrets --path . --report sarif --output reports/scan`,
  docker: `# Pull the latest image from GHCR
docker pull ghcr.io/m14r41/scan4secrets:latest

# SAST scan a local directory
docker run --rm -v "$(pwd):/scan" \\
  ghcr.io/m14r41/scan4secrets:latest \\
  --path /scan --report sarif --output /scan/reports/scan

# DAST scan a URL (no volume needed)
docker run --rm ghcr.io/m14r41/scan4secrets:latest \\
  --url https://staging.example.com --verify`,
  release: `# Linux amd64
curl -L -o scan4secrets \\
  https://github.com/m14r41/scan4secrets/releases/latest/download/scan4secrets-linux-amd64
chmod +x scan4secrets && sudo mv scan4secrets /usr/local/bin/
scan4secrets --version

# Windows x64 (PowerShell)
# Invoke-WebRequest -Uri "https://github.com/m14r41/scan4secrets/releases/latest/download/scan4secrets-win-amd64.exe" \\
#   -OutFile "$env:USERPROFILE\\scan4secrets.exe"`,
};

function Hero(): React.ReactElement {
  const {siteConfig} = useDocusaurusContext();
  const [tab, setTab] = useState<InstallTab>('pipx');
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
          <div className={styles.installTabs} role="tablist" aria-label="Install methods">
            {(['pipx', 'docker', 'release'] as const).map((t) => (
              <button
                key={t}
                role="tab"
                type="button"
                aria-selected={tab === t}
                tabIndex={tab === t ? 0 : -1}
                className={clsx(styles.installTab, tab === t && styles.installTabActive)}
                onClick={() => setTab(t)}
              >
                {t}
              </button>
            ))}
          </div>
          <pre className={styles.installCmd}>
            <code>{INSTALL_COMMANDS[tab]}</code>
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
