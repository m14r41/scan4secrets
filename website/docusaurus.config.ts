import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

const ORG = process.env.GH_ORG ?? 'm14r41';
const REPO = process.env.GH_REPO ?? 'scan4secrets';
const SITE_URL = process.env.SITE_URL ?? 'https://scan4secrets.m14r41.in';
const BASE_URL = process.env.BASE_URL ?? '/';
const GITHUB_URL = `https://github.com/${ORG}/${REPO}`;
const IS_PROD = process.env.NODE_ENV === 'production';
const GA_ID = process.env.GA_ID ?? 'G-L16KL7RKER';

const config: Config = {
  title: 'scan4secrets',
  tagline: 'DAST + SAST secret scanner with live verification, source-map parsing, and CI-native reporting',
  favicon: 'img/favicon.svg',

  url: SITE_URL,
  baseUrl: BASE_URL,

  organizationName: ORG,
  projectName: REPO,
  trailingSlash: false,
  deploymentBranch: 'gh-pages',

  onBrokenLinks: 'warn',
  onBrokenAnchors: 'warn',
  onDuplicateRoutes: 'warn',

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  markdown: {
    format: 'detect',
    hooks: {
      onBrokenMarkdownLinks: 'warn',
    },
  },

  themes: [
    [
      '@easyops-cn/docusaurus-search-local',
      {
        hashed: true,
        indexBlog: false,
        docsDir: '../docs',
        docsRouteBasePath: '/docs',
        highlightSearchTermsOnTargetPage: true,
        searchResultLimits: 20,
        searchResultContextMaxLength: 130,
        explicitSearchResultPath: true,
      },
    ],
  ],

  presets: [
    [
      'classic',
      {
        docs: {
          path: '../docs',
          routeBasePath: '/docs',
          sidebarPath: './sidebars.ts',
          // Re-enable after first commit — Docusaurus shells out to `git log` per file.
          showLastUpdateTime: false,
          editUrl: `${GITHUB_URL}/edit/main/`,
          breadcrumbs: true,
          sidebarCollapsible: true,
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
        sitemap: {
          changefreq: 'weekly',
          priority: 0.5,
          ignorePatterns: ['/tags/**'],
          filename: 'sitemap.xml',
        },
        gtag: {
          trackingID: GA_ID,
          anonymizeIP: true,
        },
      } satisfies Preset.Options,
    ],
  ],

  headTags: [
    {tagName: 'meta', attributes: {name: 'robots', content: 'index, follow'}},
    {tagName: 'meta', attributes: {name: 'theme-color', content: '#f59e0b'}},
    {tagName: 'meta', attributes: {name: 'application-name', content: 'scan4secrets'}},
    // Docusaurus auto-emits per-page `<link rel="canonical">` and `<meta property="og:url">`
    // (via React Helmet, marked with `data-rh="true"`). Don't duplicate them here.
    {tagName: 'meta', attributes: {property: 'og:type', content: 'website'}},
    {tagName: 'meta', attributes: {property: 'og:site_name', content: 'scan4secrets'}},
    // GA is wired via preset-classic `gtag` config above — emits `<script async src=".../gtag/js?id=GA_ID"></script>`
    // plus SPA-aware pageview tracking. No manual injection needed.
  ],

  themeConfig: {
    image: 'img/social-card.svg',
    metadata: [
      {name: 'keywords', content: 'secret scanner, DAST, SAST, secret detection, leaked credentials, API key scanner, token verifier, source map scanner, security tools, bug bounty, gitleaks alternative, trufflehog alternative, scan4secrets, m14r41'},
      {name: 'description', content: 'scan4secrets — DAST + SAST secret scanner that finds and live-verifies leaked credentials in source trees, web apps, JS source-maps, and HTTP headers. SARIF / JSONL / Excel / PDF / HTML reports.'},
      {name: 'author', content: 'm14r41'},
      {name: 'twitter:card', content: 'summary_large_image'},
      {name: 'twitter:title', content: 'scan4secrets, DAST and SAST secret scanner'},
      {name: 'twitter:description', content: 'Find and live-verify leaked credentials in source trees, live web apps, and CI logs.'},
    ],
    colorMode: {
      defaultMode: 'dark',
      respectPrefersColorScheme: true,
    },
    docs: {
      sidebar: {
        hideable: true,
        autoCollapseCategories: false,
      },
    },
    announcementBar: {
      id: 'release-v2',
      content: '<b>scan4secrets v2</b> is out. 170+ rules, live verification, Windows and Linux binaries. <a href="/docs/downloads">Download</a> &nbsp;·&nbsp; <a target="_blank" rel="noopener noreferrer" href="https://github.com/m14r41/scan4secrets">Star on GitHub</a>',
      backgroundColor: '#f59e0b',
      textColor: '#1f1300',
      isCloseable: true,
    },
    navbar: {
      title: 'scan4secrets',
      logo: {
        alt: 'scan4secrets logo',
        src: 'img/logo.svg',
      },
      hideOnScroll: false,
      items: [
        {type: 'docSidebar', sidebarId: 'docsSidebar', position: 'left', label: 'Docs'},
        {to: '/docs/getting-started', label: 'Get Started', position: 'left'},
        {to: '/docs/targets', label: 'Vendor Targets', position: 'left'},
        {to: '/docs/downloads', label: 'Downloads', position: 'left'},
        {
          type: 'dropdown',
          label: 'Related Projects',
          position: 'left',
          items: [
            {label: 'PentestingEverything', href: 'https://pentesting.m14r41.in'},
            {label: 'PentestingChecklist', href: 'https://checklist.m14r41.in/'},
            {label: 'wordlistForger', href: 'https://github.com/m14r41/wordlistForger'},
            {label: 'Scripting4Hackers', href: 'https://github.com/m14r41/Scripting4Hackers'},
          ],
        },
        {
          type: 'custom-githubStats',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Docs',
          items: [
            {label: 'Introduction', to: '/docs/intro'},
            {label: 'Getting Started', to: '/docs/getting-started'},
            {label: 'CLI Reference', to: '/docs/cli-reference'},
            {label: 'Architecture', to: '/docs/architecture'},
          ],
        },
        {
          title: 'Coverage',
          items: [
            {label: 'Rules Engine', to: '/docs/rules-engine'},
            {label: 'Verification', to: '/docs/verification'},
            {label: 'Vendor Targets', to: '/docs/targets'},
            {label: 'CI Integration', to: '/docs/ci-integration'},
          ],
        },
        {
          title: 'Project',
          items: [
            {label: 'GitHub', href: GITHUB_URL},
            {label: 'Releases', href: `${GITHUB_URL}/releases`},
            {label: 'Issues', href: `${GITHUB_URL}/issues`},
            {label: 'Changelog', to: '/docs/changelog'},
          ],
        },
        {
          title: 'More from m14r41',
          items: [
            {label: 'PentestingEverything', href: 'https://pentesting.m14r41.in'},
            {label: 'PentestingChecklist', href: 'https://checklist.m14r41.in/'},
            {label: 'm14r41.in', href: 'https://m14r41.in'},
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} scan4secrets &nbsp;·&nbsp; MIT License &nbsp;·&nbsp; Built by <a href="https://github.com/m14r41" target="_blank" rel="noopener noreferrer">m14r41</a>`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: [
        'bash', 'powershell', 'python', 'php', 'ruby', 'java', 'go', 'rust',
        'sql', 'json', 'yaml', 'docker', 'nginx', 'http',
        'csharp', 'toml', 'ini', 'diff', 'regex',
      ],
      magicComments: [
        {className: 'theme-code-block-highlighted-line', line: 'highlight-next-line', block: {start: 'highlight-start', end: 'highlight-end'}},
      ],
    },
    tableOfContents: {
      minHeadingLevel: 2,
      maxHeadingLevel: 4,
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
