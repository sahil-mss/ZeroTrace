import { Component, type ErrorInfo, type ReactNode } from 'react';
import { AlertTriangle, RotateCcw } from 'lucide-react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('ZeroTrace React Error Boundary caught:', error, errorInfo);
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null });
    window.location.reload();
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div className="panel" style={{ padding: '2.5rem', margin: '2rem auto', maxWidth: '640px', textAlign: 'center' }}>
          <div style={{ display: 'inline-flex', padding: '0.75rem', borderRadius: '50%', backgroundColor: 'var(--color-sev-critical-bg)', color: 'var(--color-sev-critical-text)', marginBottom: '1rem' }}>
            <AlertTriangle size={32} />
          </div>
          <h2 className="section-title" style={{ fontSize: '1.25rem', marginBottom: '0.5rem' }}>
            Application Encountered an Unexpected Error
          </h2>
          <p className="muted text-sm" style={{ marginBottom: '1.5rem', lineHeight: 1.5 }}>
            {this.state.error?.message || 'An unexpected rendering error occurred. The application state has been isolated.'}
          </p>
          <button className="btn btn-primary" onClick={this.handleReset}>
            <RotateCcw size={14} />
            <span>Reload Application</span>
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}
