/**
 * CloudAccessAuditor CIEM
 * Copyright (c) 2026. All Rights Reserved.
 * PROPRIETARY AND CONFIDENTIAL.
 */

import {StrictMode} from 'react';
import {createRoot} from 'react-dom/client';
import App from './App.tsx';
import './index.css';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
