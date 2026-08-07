/**
 * How every plate opens: the mark, the heading, and at most one line saying what
 * this screen costs or protects.
 *
 * Shared rather than repeated because it had already drifted. Each of the five
 * plates set its own margin under the wordmark and its own gap above the first
 * field, and the numbers disagreed by one step in three places: invisible on
 * any single screen and obvious the moment two are opened one after the other.
 * The spacing now lives in `.plate-head` in base.css and nothing passes it in.
 *
 * The wordmark is rust and stays rust here, on every screen, in every state
 * (tokens.css: it is the mark, not a status readout). The lede is optional
 * because "Sign in" has nothing to say that the form does not.
 */
export function PlateHead({ title, children }) {
  return (
    <header className="plate-head">
      <span className="wordmark">SIoT</span>
      <h1 className="h1">{title}</h1>
      {children ? <p className="prose">{children}</p> : null}
    </header>
  );
}
