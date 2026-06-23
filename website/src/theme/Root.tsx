import React from 'react';
import BrowserOnly from '@docusaurus/BrowserOnly';
import ReadingProgress from '@site/src/components/ReadingProgress';
import ScrollToTop from '@site/src/components/ScrollToTop';

/**
 * Theme Root wraps every page. Mounts the top reading-progress bar and the
 * floating scroll-to-top button as siblings of children — BrowserOnly so SSR
 * skips them (they read `window`).
 */
export default function Root({children}: {children: React.ReactNode}): React.ReactElement {
  return (
    <>
      <BrowserOnly>{() => <ReadingProgress />}</BrowserOnly>
      {children}
      <BrowserOnly>{() => <ScrollToTop />}</BrowserOnly>
    </>
  );
}
