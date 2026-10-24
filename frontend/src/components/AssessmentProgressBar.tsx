import React, { useEffect, useState, useRef } from 'react';
import { useApp } from '../context/useApp';
import { Terminal } from 'lucide-react';

const PSYCH_STAGES = [
  { at: 7, label: 'Initializing ZeroTrace scope engine & handshake...', color: '#737373' },
  { at: 18, label: 'Bypassing perimeter noise filters & TLS fingerprinting...', color: '#a3a3a3' },
  { at: 31, label: 'Correlating DNS zones & crt.sh certificate records...', color: '#d4d4d4' },
  { at: 49, label: 'Probing HTTP security headers & CORS origin policies...', color: '#f59e0b' },
  { at: 68, label: 'Executing payload reflection vectors & auth checks...', color: '#f59e0b' },
  { at: 83, label: 'Triaging findings against empirical evidence stores...', color: '#ef4444' },
  { at: 94, label: 'Synthesizing evidence-grounded AI risk model...', color: '#ef4444' },
  { at: 99, label: 'Finalizing audit verification & locking scope...', color: '#10b981' },
];

export const AssessmentProgressBar: React.FC = () => {
  const { currentAssessment } = useApp();
  const [progress, setProgress] = useState(0);
  const [stageText, setStageText] = useState('');
  const intervalRef = useRef<number | null>(null);

  const isRunning = currentAssessment?.status === 'in_progress';
  const isCompleted = currentAssessment?.status === 'completed' || progress >= 100;
  const effectiveProgress = currentAssessment?.status === 'completed' ? 100 : progress;

  useEffect(() => {
    if (!isRunning) {
      if (intervalRef.current) clearInterval(intervalRef.current);
      return;
    }

    // Psychological timing: rapid initial jump, tense hesitation around 45-55% and 82-87%, then swift finish
    intervalRef.current = window.setInterval(() => {
      setProgress((prev) => {
        const base = prev === 0 ? 5 : prev;
        let next = base;
        if (base < 25) {
          next += 1.8 + Math.random() * 2.2;
        } else if (base >= 25 && base < 48) {
          next += 0.9 + Math.random() * 1.1;
        } else if (base >= 48 && base < 62) {
          // Tension plateau
          next += 0.25 + Math.random() * 0.45;
        } else if (prev >= 62 && prev < 84) {
          next += 0.8 + Math.random() * 1.4;
        } else if (prev >= 84 && prev < 96) {
          // Final deep verification plateau
          next += 0.2 + Math.random() * 0.35;
        } else if (prev >= 96 && prev < 100) {
          next += 0.6 + Math.random() * 0.8;
        }

        if (next >= 100) {
          next = 100;
          setStageText('Assessment complete · Scope verification locked');
          if (intervalRef.current) clearInterval(intervalRef.current);
        } else {
          // Update psychological stage label
          for (let i = PSYCH_STAGES.length - 1; i >= 0; i--) {
            if (next >= PSYCH_STAGES[i].at) {
              setStageText(PSYCH_STAGES[i].label);
              break;
            }
          }
        }
        return Math.min(next, 100);
      });
    }, 280);

    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [isRunning, currentAssessment?.status]);

  if (!isRunning && !isCompleted && effectiveProgress === 0) {
    return null;
  }

  const rounded = Math.floor(effectiveProgress);
  const displayStageText = isCompleted
    ? 'Assessment complete · Scope verification locked'
    : stageText || PSYCH_STAGES[0].label;

  return (
    <div
      style={{
        backgroundColor: '#0a0a0a',
        border: '1px solid #262626',
        borderRadius: '6px',
        padding: '0.85rem 1.25rem',
        marginBottom: '1rem',
        boxShadow: '0 4px 20px rgba(0, 0, 0, 0.7)',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      {/* Background scanline effect */}
      <div
        style={{
          position: 'absolute',
          inset: 0,
          background: 'linear-gradient(90deg, transparent, rgba(255,255,255,0.02), transparent)',
          pointerEvents: 'none',
        }}
      />

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
          <div
            style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              backgroundColor: isCompleted ? '#10b981' : '#f59e0b',
              boxShadow: isCompleted ? '0 0 10px #10b981' : '0 0 10px #f59e0b',
              animation: isCompleted ? 'none' : 'pulse 1.4s infinite ease-in-out',
            }}
          />
          <span style={{ fontSize: '0.78rem', fontWeight: 700, letterSpacing: '0.06em', color: '#e5e5e5', textTransform: 'uppercase' }}>
            {isCompleted ? 'Assessment Completed' : 'Active Scope Scan in Progress'}
          </span>
          <span
            className="font-mono"
            style={{
              fontSize: '0.72rem',
              color: '#a3a3a3',
              backgroundColor: '#171717',
              padding: '0.15rem 0.5rem',
              borderRadius: '3px',
              border: '1px solid #262626',
            }}
          >
            {currentAssessment?.target}
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span className="font-mono" style={{ fontSize: '0.95rem', fontWeight: 800, color: isCompleted ? '#10b981' : '#ffffff' }}>
            {rounded}%
          </span>
        </div>
      </div>

      {/* Progress Track */}
      <div
        style={{
          height: '6px',
          width: '100%',
          backgroundColor: '#171717',
          borderRadius: '3px',
          overflow: 'hidden',
          position: 'relative',
          border: '1px solid #262626',
        }}
      >
        <div
          style={{
            height: '100%',
            width: `${effectiveProgress}%`,
            backgroundColor: isCompleted ? '#10b981' : '#f59e0b',
            background: isCompleted
              ? 'linear-gradient(90deg, #059669, #10b981)'
              : 'linear-gradient(90deg, #d97706, #fbbf24)',
            transition: 'width 0.28s cubic-bezier(0.4, 0, 0.2, 1)',
            boxShadow: isCompleted ? '0 0 12px rgba(16, 185, 129, 0.5)' : '0 0 12px rgba(245, 158, 11, 0.5)',
          }}
        />
      </div>

      {/* Psychological Subtext & Terminal Prompt */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '0.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', fontSize: '0.74rem', color: '#a3a3a3' }}>
          <Terminal size={12} style={{ color: '#737373' }} />
          <span className="font-mono" style={{ color: '#d4d4d4' }}>{displayStageText}</span>
        </div>
        <span style={{ fontSize: '0.7rem', color: '#52525b', fontFamily: 'monospace' }}>
          {isCompleted ? 'ALL VECTORS EVALUATED' : 'LIVE TELEMETRY'}
        </span>
      </div>
    </div>
  );
};
