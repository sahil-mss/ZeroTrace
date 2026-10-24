import React from 'react';
import { AppProvider } from './context/AppContext';
import { useApp } from './context/useApp';
import { Sidebar } from './components/Sidebar';
import { TopBar } from './components/TopBar';
import { FindingDetailModal } from './components/FindingDetailModal';
import { ToastContainer } from './components/ToastContainer';
import { AssessmentProgressBar } from './components/AssessmentProgressBar';
import { OverviewPage } from './pages/OverviewPage';
import { AssessmentsPage } from './pages/AssessmentsPage';
import { AssetsPage } from './pages/AssetsPage';
import { FindingsPage } from './pages/FindingsPage';
import { AIAnalysisPage } from './pages/AIAnalysisPage';
import { ReportsPage } from './pages/ReportsPage';
import { ActivityPage } from './pages/ActivityPage';
import { DEMO_BANNER_LABEL } from './data/demoData';

import { ErrorBoundary } from './components/ErrorBoundary';
import { apiClient } from './api/client';
import { AlertTriangle, RefreshCw } from 'lucide-react';

const MainLayout: React.FC = () => {
  const { activePage } = useApp();
  const [isBackendHealthy, setIsBackendHealthy] = React.useState<boolean | null>(null);
  const [isCheckingHealth, setIsCheckingHealth] = React.useState(false);

  const checkBackendHealth = React.useCallback(async () => {
    setIsCheckingHealth(true);
    const result = await apiClient.checkHealth();
    setIsBackendHealthy(result.ok);
    setIsCheckingHealth(false);
  }, []);

  React.useEffect(() => {
    let mounted = true;
    apiClient.checkHealth().then((result) => {
      if (mounted) {
        setIsBackendHealthy(result.ok);
      }
    });
    return () => {
      mounted = false;
    };
  }, []);

  return (
    <div className="app-container">
      <a href="#main-content" className="skip-link">
        Skip to content
      </a>
      <Sidebar />

      <div className="main-wrapper">
        {isBackendHealthy === false && (
          <div
            style={{
              backgroundColor: '#271b07',
              borderBottom: '1px solid #78350f',
              padding: '0.625rem 1rem',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              fontSize: '0.8125rem',
              color: '#fef3c7',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <AlertTriangle size={16} color="#f59e0b" />
              <span>
                Backend offline at <strong>{apiClient.getBaseUrl()}</strong>. Operating with local synthetic lab data.
              </span>
            </div>
            <button
              onClick={checkBackendHealth}
              disabled={isCheckingHealth}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.375rem',
                background: '#451a03',
                color: '#fef3c7',
                border: '1px solid #78350f',
                borderRadius: '4px',
                padding: '0.25rem 0.625rem',
                fontSize: '0.75rem',
                cursor: 'pointer',
              }}
            >
              <RefreshCw size={12} className={isCheckingHealth ? 'spin' : ''} />
              {isCheckingHealth ? 'Checking...' : 'Retry'}
            </button>
          </div>
        )}
        <div className="demo-banner">{DEMO_BANNER_LABEL}</div>
        <TopBar />

        <main id="main-content" className="main-content">
          <AssessmentProgressBar />
          <ErrorBoundary>
            {activePage === 'overview' && <OverviewPage />}
            {activePage === 'assessments' && <AssessmentsPage />}
            {activePage === 'assets' && <AssetsPage />}
            {activePage === 'findings' && <FindingsPage />}
            {activePage === 'ai-analysis' && <AIAnalysisPage />}
            {activePage === 'reports' && <ReportsPage />}
            {activePage === 'activity' && <ActivityPage />}
          </ErrorBoundary>
        </main>
      </div>

      <FindingDetailModal />
      <ToastContainer />
    </div>
  );
};

export default function App() {
  return (
    <AppProvider>
      <MainLayout />
    </AppProvider>
  );
}
