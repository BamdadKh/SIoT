import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

// Self-hosted, not Google Fonts. A zero-knowledge product that phones a third
// party for its typeface on every load is telling on its users for the sake of
// a stylesheet. `standard` carries both the weight and width axes.
import '@fontsource-variable/archivo/standard.css';
import '@fontsource/martian-mono/400.css';

import './styles/tokens.css';
import './styles/base.css';
import { App } from './App.jsx';

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
