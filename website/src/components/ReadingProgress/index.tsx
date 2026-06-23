import React, {useEffect, useState} from 'react';
import styles from './styles.module.css';

export default function ReadingProgress(): React.ReactElement {
  const [pct, setPct] = useState(0);

  useEffect(() => {
    const onScroll = () => {
      const h = document.documentElement;
      const max = h.scrollHeight - h.clientHeight;
      const p = max > 0 ? (h.scrollTop / max) * 100 : 0;
      setPct(Math.min(100, Math.max(0, p)));
    };
    window.addEventListener('scroll', onScroll, {passive: true});
    onScroll();
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  return (
    <div className={styles.track} aria-hidden="true">
      <div className={styles.bar} style={{width: `${pct}%`}} />
    </div>
  );
}
