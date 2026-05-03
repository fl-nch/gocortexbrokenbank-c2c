// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
import './globals.css';

export const metadata = {
  title: 'SpaceATM Terminal - Mars Banking Initiative',
  description: 'GoCortex Broken Bank SpaceATM Terminal v1.5.0',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>
        <div className="atm-bezel">
          <div className="atm-header">
            <div className="atm-header-left">
              <div className="atm-title">SpaceATM Terminal</div>
              <div className="atm-subtitle">Mars Banking Initiative</div>
            </div>
            <div className="atm-header-right">
              <div>SA-7000 Series | FW-2025.03.1</div>
              <div>Broken Bank v1.5.0</div>
            </div>
          </div>
          <div className="atm-screen">
            {children}
          </div>
          <div className="atm-footer">
            <div>
              <span className="atm-status-dot green"></span>
              GoCortex IO Pty Ltd | Southbank, Melbourne VIC 3006
            </div>
            <div className="atm-status-bar">
              <span><span className="atm-status-dot green"></span>NET</span>
              <span><span className="atm-status-dot green"></span>ENC</span>
              <span><span className="atm-status-dot green"></span>HW</span>
            </div>
            <div>SN: VIC-SA-003847 | CVE-2025-55182</div>
          </div>
        </div>
      </body>
    </html>
  );
}
