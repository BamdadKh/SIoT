/**
 * The centred panel the signed-out screens sit on, with its registration ticks.
 * The top-left tick is the datum and is drawn in rust; the other three are plain
 * olive registration. See `.tick-*` in base.css.
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
