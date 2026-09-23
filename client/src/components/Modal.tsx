import { useEffect, useId, useRef, type ReactNode } from 'react';
import { Icon } from './Icon.tsx';

/** Accessible modal dialog: focus trap, Escape to close, labelled by its title. */
export function Modal({
  title,
  subtitle,
  onClose,
  children,
  footer,
  wide,
  steps,
}: {
  title: string;
  subtitle?: ReactNode;
  onClose?: () => void;
  children: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
  steps?: { total: number; current: number };
}) {
  const ref = useRef<HTMLDivElement>(null);
  const titleId = useId();
  // Parents pass inline callbacks; keep the latest in a ref so the focus
  // effect below runs only on mount (re-running it would steal focus while typing).
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    const el = ref.current;
    // Keep a child's autoFocus; otherwise focus the dialog itself (screen readers announce its title).
    if (!el?.contains(document.activeElement)) el?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && closeRef.current) {
        e.stopPropagation();
        closeRef.current();
      }
      if (e.key === 'Tab' && el) {
        const items = [...el.querySelectorAll<HTMLElement>('a, button, input, textarea, select, [tabindex]:not([tabindex="-1"])')].filter(
          (x) => !x.hasAttribute('disabled'),
        );
        if (!items.length) return;
        const a = items[0]!;
        const b = items[items.length - 1]!;
        if (e.shiftKey && document.activeElement === a) {
          e.preventDefault();
          b.focus();
        } else if (!e.shiftKey && document.activeElement === b) {
          e.preventDefault();
          a.focus();
        }
      }
    };
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('keydown', onKey);
      prev?.focus?.();
    };
  }, []);

  return (
    <div className="overlay" onMouseDown={(e) => e.target === e.currentTarget && onClose?.()}>
      <div className={`modal${wide ? ' wide' : ''}`} role="dialog" aria-modal="true" aria-labelledby={titleId} ref={ref} tabIndex={-1}>
        {steps && (
          <div className="stepper" aria-label={`Step ${steps.current + 1} of ${steps.total}`}>
            {Array.from({ length: steps.total }, (_, i) => (
              <div key={i} className={`s${i <= steps.current ? ' on' : ''}`} />
            ))}
          </div>
        )}
        <div className="modal-head">
          <div className="grow">
            <h2 id={titleId}>{title}</h2>
            {subtitle && <p>{subtitle}</p>}
          </div>
          {onClose && (
            <button className="btn ghost sm icon" data-close onClick={onClose} aria-label="Close dialog">
              <Icon name="x" />
            </button>
          )}
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-foot">{footer}</div>}
      </div>
    </div>
  );
}

export function Callout({ tone, icon, children }: { tone?: 'accent' | 'warn' | 'danger'; icon?: Parameters<typeof Icon>[0]['name']; children: ReactNode }) {
  return (
    <div className={`callout${tone ? ' ' + tone : ''}`} role={tone === 'danger' ? 'alert' : undefined}>
      <Icon name={icon ?? (tone === 'warn' || tone === 'danger' ? 'alert' : 'info')} size={16} />
      <div>{children}</div>
    </div>
  );
}
