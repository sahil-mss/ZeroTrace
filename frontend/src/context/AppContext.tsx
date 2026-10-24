import React, { useState, useEffect } from 'react';
import type {
  Assessment,
  Asset,
  Evidence,
  Finding,
  AIAnalysis,
  ActivityEvent,
  ToastMessage,
} from '../types';
import {
  DEMO_ASSESSMENTS,
  DEMO_ASSETS,
  DEMO_EVIDENCE,
  DEMO_FINDINGS,
  DEMO_AI_ANALYSIS,
  DEMO_ACTIVITY_LOGS,
} from '../data/demoData';
import { AppContext } from './appContextDefinition';
import type { NavPage } from './appContextDefinition';

export const AppProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  // Theme initialization
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    const saved = localStorage.getItem('aegis_theme');
    if (saved === 'dark' || saved === 'light') return saved;
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches
      ? 'dark'
      : 'light';
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('aegis_theme', theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'));
  };

  // State Management
  const [activePage, setActivePage] = useState<NavPage>('overview');
  const [currentAssessmentId, setCurrentAssessmentId] = useState<string>('asm_lab_001');
  const [assessments, setAssessments] = useState<Assessment[]>(DEMO_ASSESSMENTS);
  const [assets] = useState<Asset[]>(DEMO_ASSETS);
  const [findings] = useState<Finding[]>(DEMO_FINDINGS);
  const [evidence] = useState<Evidence[]>(DEMO_EVIDENCE);
  const [aiAnalysis, setAiAnalysis] = useState<Record<string, AIAnalysis>>(DEMO_AI_ANALYSIS);
  const [activityLogs, setActivityLogs] = useState<ActivityEvent[]>(DEMO_ACTIVITY_LOGS);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [globalSearch, setGlobalSearch] = useState<string>('');

  const [sidebarOpen, setSidebarOpen] = useState<boolean>(false);

  const handleSetActivePage = (page: NavPage) => {
    setActivePage(page);
    setSidebarOpen(false);
  };

  const updateFindingAnalysis = (findingId: string, analysis: AIAnalysis) => {
    setAiAnalysis((prev) => ({
      ...prev,
      [findingId]: analysis,
    }));
  };

  // Toasts
  const [toasts, setToasts] = useState<ToastMessage[]>([]);
  const toastSeqRef = React.useRef(0);

  const removeToast = React.useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const addToast = React.useCallback(
    (
      title: string,
      message?: string,
      type: 'info' | 'success' | 'warning' | 'error' = 'info'
    ) => {
      toastSeqRef.current += 1;
      const id = `toast_${toastSeqRef.current}`;
      setToasts((prev) => [...prev, { id, title, message, type }]);
      setTimeout(() => {
        removeToast(id);
      }, 4500);
    },
    [removeToast]
  );

  const currentAssessment = assessments.find((a) => a.id === currentAssessmentId);

  // Workflow Actions
  const startAssessment = (id: string) => {
    setAssessments((prev) =>
      prev.map((a) => (a.id === id ? { ...a, status: 'in_progress' } : a))
    );
    const event: ActivityEvent = {
      id: `act_${Date.now()}`,
      assessment_id: id,
      timestamp: new Date().toISOString(),
      level: 'success',
      component: 'SCOPE_ENGINE',
      message: `Assessment ${id} transitioned to IN_PROGRESS. Scope rules armed.`,
    };
    setActivityLogs((prev) => [event, ...prev]);
    addToast('Assessment Started', `Scope policies activated for ${id}`, 'success');
  };

  const cancelAssessment = (id: string) => {
    setAssessments((prev) =>
      prev.map((a) =>
        a.id === id ? { ...a, status: 'cancelled', completed_at: new Date().toISOString() } : a
      )
    );
    const event: ActivityEvent = {
      id: `act_${Date.now()}`,
      assessment_id: id,
      timestamp: new Date().toISOString(),
      level: 'warning',
      component: 'SCOPE_ENGINE',
      message: `Emergency halt initiated for assessment ${id}. Workers signalled to stop.`,
    };
    setActivityLogs((prev) => [event, ...prev]);
    addToast('Assessment Stopped', `Emergency stop completed for ${id}`, 'warning');
  };

  const createNewAssessment = (name: string, target: string, policy: string) => {
    if (!name.trim() || !target.trim()) {
      addToast('Validation Error', 'Assessment name and target are required.', 'error');
      return;
    }

    const newId = `asm_lab_00${assessments.length + 1}`;
    const newAssessment: Assessment = {
      id: newId,
      name,
      target,
      status: 'pending',
      created_at: new Date().toISOString(),
      scope_policy: policy || 'STRICT_SINGLE_HOST',
      allowed_checks: ['passive_recon', 'port_scan'],
    };

    setAssessments((prev) => [newAssessment, ...prev]);
    setCurrentAssessmentId(newId);
    addToast('Assessment Created', `Authorized target recorded: ${target}`, 'success');
  };

  return (
    <AppContext.Provider
      value={{
        theme,
        toggleTheme,
        activePage,
        setActivePage: handleSetActivePage,
        currentAssessmentId,
        setCurrentAssessmentId,
        currentAssessment,
        assessments,
        assets,
        findings,
        evidence,
        aiAnalysis,
        setAiAnalysis,
        updateFindingAnalysis,
        activityLogs,
        selectedFindingId,
        setSelectedFindingId,
        globalSearch,
        setGlobalSearch,
        toasts,
        addToast,
        removeToast,
        startAssessment,
        cancelAssessment,
        createNewAssessment,
        sidebarOpen,
        setSidebarOpen,
      }}
    >
      {children}
    </AppContext.Provider>
  );
};
