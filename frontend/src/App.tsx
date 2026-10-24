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

const MainLayout: React.FC = () => {
  const { activePage } = useApp();

  return (
    <div className="app-container">
      <Sidebar />

      <div className="main-wrapper">
        <div className="demo-banner">{DEMO_BANNER_LABEL}</div>
        <TopBar />

        <main className="main-content">
          <AssessmentProgressBar />
          {activePage === 'overview' && <OverviewPage />}
          {activePage === 'assessments' && <AssessmentsPage />}
          {activePage === 'assets' && <AssetsPage />}
          {activePage === 'findings' && <FindingsPage />}
          {activePage === 'ai-analysis' && <AIAnalysisPage />}
          {activePage === 'reports' && <ReportsPage />}
          {activePage === 'activity' && <ActivityPage />}
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
