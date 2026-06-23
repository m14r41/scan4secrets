import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

const sidebars: SidebarsConfig = {
  docsSidebar: [
    'intro',
    'getting-started',
    'cli-reference',
    'architecture',
    'rules-engine',
    'verification',
    'ci-integration',
    'sample-report',
    'downloads',
    {
      type: 'category',
      label: 'Vendor Targets',
      link: {type: 'generated-index', title: 'Vendor Targets', description: 'Per-vendor coverage, token formats, and verification probes.', slug: '/targets'},
      collapsed: false,
      items: [
        'targets/facebook',
        'targets/google-cloud',
        'targets/aws',
        'targets/github',
        'targets/slack',
      ],
    },
    'changelog',
    'gap-analysis',
  ],
};

export default sidebars;
