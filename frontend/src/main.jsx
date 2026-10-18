import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import './index.css';

import Landing    from './Landing';
import App        from './App';
import History    from './History';
import ScanDetail from './ScanDetail';
import DpdpaDetail from './DpdpaDetail';
import AboutUs    from './AboutUs';

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <BrowserRouter>
      <Routes>
        <Route path="/"         element={<Landing />} />
        <Route path="/app"      element={<App />} />
        <Route path="/history"  element={<History />} />
        <Route path="/scan/:id"    element={<ScanDetail />} />
        <Route path="/dpdpa/:slug" element={<DpdpaDetail />} />
        <Route path="/about"      element={<AboutUs />} />
      </Routes>
    </BrowserRouter>
  </React.StrictMode>
);
