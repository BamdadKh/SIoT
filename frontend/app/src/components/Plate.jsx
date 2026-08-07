/**
 * The centred panel a single-purpose screen sits on, with its registration ticks.
 *
 * All four ticks are identical and all four are rust, on every screen and in
 * every state. The plate chrome never carries status: locked, busy and failed
 * are said by the heading and the control, where someone is already looking.
 * See `.tick-*` in base.css.
 */
export function Plate({ children }) {
  return (
    <div className="plate-center">
      <div className="plate">
        <span className="tick tick-tl" />
        <span className="tick tick-tr" />
        <span className="tick tick-bl" />
        <span className="tick tick-br" />
        {children}
      </div>
    </div>
  );
}
