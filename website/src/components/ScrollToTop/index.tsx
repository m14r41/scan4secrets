import React, {useEffect, useState} from 'react';
import styles from './styles.module.css';

export default function ScrollToTop(): React.ReactElement | null {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const onScroll = () => setVisible(window.scrollY > 320);
    window.addEventListener('scroll', onScroll, {passive: true});
    onScroll();
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  const onClick = () =>
    window.scrollTo({top: 0, behavior: 'smooth'});

  return (
    <button
      type="button"
      aria-label="Scroll to top"
      title="Scroll to top"
      onClick={onClick}
      className={`${styles.fab} ${visible ? styles.visible : ''}`}
    >
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <line x1="12" y1="19" x2="12" y2="5" />
        <polyline points="5 12 12 5 19 12" />
      </svg>
    </button>
  );
}
