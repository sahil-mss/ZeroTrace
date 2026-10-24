import { createContext } from 'react';
import type {
  Assessment,
  Asset,
  Evidence,
  Finding,
  AIAnalysis,
  ActivityEvent,
  ToastMessage,
} from '../types';

export type NavPage =
  | 'overview'
  | 'assessments'
  | 'assets'
  | 'findings'
  | 'ai-analysis'
  | 'reports'
  | 'activity';

export interface AppContextType {
  theme: 'dark' | 'light';
  toggleTheme: () => void;
  activePage: NavPage;
  setActivePage: (page: NavPage) => void;
  currentAssessmentId: string;
  setCurrentAssessmentId: (id: string) => void;
  currentAssessment: Assessment | undefined;
  assessments: Assessment[];
  assets: Asset[];
  findings: Finding[];
  evidence: Evidence[];
  aiAnalysis: Record<string, AIAnalysis>;
  setAiAnalysis: React.Dispatch<React.SetStateAction<Record<string, AIAnalysis>>>;
  updateFindingAnalysis: (findingId: string, analysis: AIAnalysis) => void;
  activityLogs: ActivityEvent[];
  selectedFindingId: string | null;
  setSelectedFindingId: (id: string | null) => void;
  globalSearch: string;
  setGlobalSearch: (term: string) => void;
  toasts: ToastMessage[];
  addToast: (
    title: string,
    message?: string,
    type?: 'info' | 'success' | 'warning' | 'error'
  ) => void;
  removeToast: (id: string) => void;
  startAssessment: (id: string) => void;
  cancelAssessment: (id: string) => void;
  createNewAssessment: (name: string, target: string, policy: string) => void;
  sidebarOpen: boolean;
  setSidebarOpen: (open: boolean) => void;
}

export const AppContext = createContext<AppContextType | undefined>(undefined);
