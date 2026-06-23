import React, {useEffect, useState} from 'react';
import Link from '@docusaurus/Link';
import BrowserOnly from '@docusaurus/BrowserOnly';
import styles from './styles.module.css';

const REPO = 'm14r41/scan4secrets';
const CACHE_KEY = 'gh_stats_scan4secrets';
const TTL_MS = 1000 * 60 * 30;

type Stats = {stars: number; forks: number; ts: number};

function fmt(n: number): string {
  if (n >= 10000) return (n / 1000).toFixed(0) + 'k';
  if (n >= 1000) return (n / 1000).toFixed(1).replace('.0', '') + 'k';
  return String(n);
}

function readCache(): Stats | null {
  try {
    const raw = localStorage.getItem(CACHE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Stats;
    if (typeof parsed?.stars !== 'number') return null;
    return parsed;
  } catch {
    return null;
  }
}

function GitHubStatsInner(): React.ReactElement {
  const [stats, setStats] = useState<Stats | null>(() => readCache());

  useEffect(() => {
    const cached = readCache();
    if (cached && Date.now() - cached.ts < TTL_MS) {
      setStats(cached);
      return;
    }
    let cancelled = false;
    (async () => {
      try {
        const r = await fetch(`https://api.github.com/repos/${REPO}`, {
          headers: {Accept: 'application/vnd.github+json'},
        });
        if (!r.ok || cancelled) return;
        const j = await r.json();
        const next: Stats = {
          stars: Number(j.stargazers_count) || 0,
          forks: Number(j.forks_count) || 0,
          ts: Date.now(),
        };
        try {
          localStorage.setItem(CACHE_KEY, JSON.stringify(next));
        } catch {}
        if (!cancelled) setStats(next);
      } catch {}
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const stars = stats ? fmt(stats.stars) : '–';
  const forks = stats ? fmt(stats.forks) : '–';

  return (
    <Link
      className={styles.wrapper}
      href={`https://github.com/${REPO}`}
      target="_blank"
      rel="noopener noreferrer"
      aria-label={`GitHub repository: ${stars} stars, ${forks} forks`}
    >
      <svg className={styles.ghIcon} viewBox="0 0 24 24" aria-hidden="true">
        <path
          fill="currentColor"
          d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.4 3-.405 1.02.005 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"
        />
      </svg>
      <span className={styles.stat}>
        <svg className={styles.mini} viewBox="0 0 16 16" aria-hidden="true">
          <path
            fill="currentColor"
            d="M8 .25a.75.75 0 0 1 .673.418l1.882 3.815 4.21.612a.75.75 0 0 1 .416 1.279l-3.046 2.97.719 4.192a.75.75 0 0 1-1.088.791L8 12.347l-3.766 1.98a.75.75 0 0 1-1.088-.79l.72-4.194L.818 6.374a.75.75 0 0 1 .416-1.28l4.21-.611L7.327.668A.75.75 0 0 1 8 .25Z"
          />
        </svg>
        <span className={styles.count}>{stars}</span>
      </span>
      <span className={styles.stat}>
        <svg className={styles.mini} viewBox="0 0 16 16" aria-hidden="true">
          <path
            fill="currentColor"
            d="M5 5.372v.878c0 .414.336.75.75.75h4.5a.75.75 0 0 0 .75-.75v-.878a2.25 2.25 0 1 1 1.5 0v.878a2.25 2.25 0 0 1-2.25 2.25h-1.5v2.128a2.251 2.251 0 1 1-1.5 0V8.5h-1.5A2.25 2.25 0 0 1 3.5 6.25v-.878a2.25 2.25 0 1 1 1.5 0ZM5 3.25a.75.75 0 1 0-1.5 0 .75.75 0 0 0 1.5 0Zm6.75.75a.75.75 0 1 0 0-1.5.75.75 0 0 0 0 1.5Zm-3 8.75a.75.75 0 1 0-1.5 0 .75.75 0 0 0 1.5 0Z"
          />
        </svg>
        <span className={styles.count}>{forks}</span>
      </span>
    </Link>
  );
}

export default function GitHubStats(): React.ReactElement {
  return (
    <BrowserOnly
      fallback={
        <Link
          className={styles.wrapper}
          href={`https://github.com/${REPO}`}
          target="_blank"
          rel="noopener noreferrer"
          aria-label="GitHub repository"
        >
          <svg className={styles.ghIcon} viewBox="0 0 24 24" aria-hidden="true">
            <path
              fill="currentColor"
              d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.4 3-.405 1.02.005 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"
            />
          </svg>
          <span className={styles.label}>GitHub</span>
        </Link>
      }
    >
      {() => <GitHubStatsInner />}
    </BrowserOnly>
  );
}
