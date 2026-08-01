import { useId } from 'react';

/**
 * A labelled control. The label is always rendered and always associated — a
 * placeholder standing in for a label disappears exactly when it is needed.
 */
export function Field({ label, type = 'text', value, onChange, disabled, autoComplete, autoFocus, ...rest }) {
  const id = useId();

  return (
    <div className="field">
      <label className="field-label" htmlFor={id}>
        {label}
      </label>
      <input
        id={id}
        className="field-input"
        type={type}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        disabled={disabled}
        autoComplete={autoComplete}
        autoFocus={autoFocus}
        {...rest}
      />
    </div>
  );
}
