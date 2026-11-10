import { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { PassportRecord, CommunityReport } from './types/triage';
import { CANONICAL_SCENARIOS, INITIAL_COMMUNITY_REPORTS } from './data/scenarios';
import { sound } from './utils/audio';
import { useLenis } from './hooks/useLenis';

import CustomCursor from './components/CustomCursor';
import LiquidFilter from './components/LiquidFilter';
import ScrollProgress from './components/ScrollProgress';
import Header from './components/Header';
import TriageStudio from './components/TriageStudio';
import GalleryView from './components/GalleryView';
import EvidencePassportView from './components/EvidencePassportView';
import ThreatIntelFeed from './components/ThreatIntelFeed';
import InvariantsExplorer from './components/InvariantsExplorer';
import BackendModal from './components/BackendModal';
import Toast from './components/Toast';
import Footer from './components/Footer';

export default function App() {
  // Initialize Lenis smooth inertial scrolling
  useLenis();

  const [activeTab, setActiveTab] = useState<'studio' | 'gallery' | 'passport' | 'community' | 'invariants' | 'backend'>('studio');
  const [currentUrl, setCurrentUrl] = useState<string>('https://bank-secure-lоgin.com');
  const [currentReport, setCurrentReport] = useState<PassportRecord>(CANONICAL_SCENARIOS.phishing_lookalike);
  const [soundEnabled, setSoundEnabled] = useState<boolean>(sound.isEnabled());
  const [showJson, setShowJson] = useState<boolean>(false);
  const [communityReports, setCommunityReports] = useState<CommunityReport[]>(INITIAL_COMMUNITY_REPORTS);
  const [isBackendModalOpen, setIsBackendModalOpen] = useState<boolean>(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => {
      setToastMessage((prev) => (prev === msg ? null : prev));
    }, 3000);
  };

  const handleTriageComplete = (report: PassportRecord) => {
    setCurrentReport(report);
    setActiveTab('passport');
    if (report.status === 'rejected') {
      showToast(`Target rejected at intake boundary: ${report.normalized_host}`);
    } else if (report.decision === 'inconclusive') {
      showToast(`Triage inconclusive for ${report.normalized_host} (evidence unavailable)`);
    } else {
      showToast(`Triage complete for ${report.normalized_host}`);
    }
  };

  const handleSelectCaseFromGallery = (scenarioKey: string, domainUrl: string) => {
    if (CANONICAL_SCENARIOS[scenarioKey]) {
      const scenario = CANONICAL_SCENARIOS[scenarioKey];
      setCurrentUrl(domainUrl);
      setCurrentReport(scenario);
      setActiveTab('passport');
      showToast(`Loaded benchmark: ${scenario.normalized_host}`);
    } else {
      setCurrentUrl(domainUrl);
      setActiveTab('studio');
    }
  };

  const handleSelectScenarioFromInvariants = (scenarioKey: string) => {
    if (CANONICAL_SCENARIOS[scenarioKey]) {
      const scenario = CANONICAL_SCENARIOS[scenarioKey];
      setCurrentUrl(scenario.submitted_url_redacted);
      setCurrentReport(scenario);
      setActiveTab('passport');
      showToast(`Loaded ${scenario.normalized_host} benchmark`);
    } else {
      setActiveTab('studio');
    }
  };

  const handleTriageDomainFromIntel = (domainUrl: string) => {
    setCurrentUrl(domainUrl);
    setActiveTab('studio');
  };

  return (
    <div className="relative min-h-screen bg-[#FFFFFF] text-[#040404] font-body flex flex-col justify-between selection:bg-[#040404] selection:text-white transition-colors overflow-x-hidden">
      {/* Osply-Style Global SVG Liquid Distortion Filter */}
      <LiquidFilter />

      {/* Top Inertial Scroll Reading Progress Bar */}
      <ScrollProgress />

      {/* Osply Fluid Magnetic & Jelly Squish Cursor */}
      <CustomCursor />

      {/* Navigation Header with Sound Waveform Equalizer */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        soundEnabled={soundEnabled}
        setSoundEnabled={setSoundEnabled}
        onToggleJson={() => setShowJson(!showJson)}
        onOpenBackendModal={() => setIsBackendModalOpen(true)}
        onShowToast={showToast}
      />

      {/* Main Screen Content */}
      <main className="max-w-5xl mx-auto px-4 sm:px-6 py-6 sm:py-16 flex-grow w-full">
        <AnimatePresence mode="wait">
          {activeTab === 'studio' && (
            <motion.div
              key="studio"
              initial={{ opacity: 0, y: 14 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -14 }}
              transition={{ duration: 0.26, ease: [0.16, 1, 0.3, 1] }}
            >
              <TriageStudio
                currentUrl={currentUrl}
                setCurrentUrl={setCurrentUrl}
                onTriageComplete={handleTriageComplete}
                onOpenInvariants={() => setActiveTab('invariants')}
                onOpenGallery={() => setActiveTab('gallery')}
                onShowToast={showToast}
              />
            </motion.div>
          )}

          {activeTab === 'gallery' && (
            <motion.div
              key="gallery"
              initial={{ opacity: 0, y: 14 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -14 }}
              transition={{ duration: 0.26, ease: [0.16, 1, 0.3, 1] }}
            >
              <GalleryView
                onSelectCase={handleSelectCaseFromGallery}
                onShowToast={showToast}
              />
            </motion.div>
          )}

          {activeTab === 'passport' && (
            <motion.div
              key="passport"
              initial={{ opacity: 0, y: 14 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -14 }}
              transition={{ duration: 0.26, ease: [0.16, 1, 0.3, 1] }}
            >
              <EvidencePassportView
                report={currentReport}
                showJson={showJson}
                setShowJson={setShowJson}
                onShowToast={showToast}
                onOpenInvariants={() => setActiveTab('invariants')}
              />
            </motion.div>
          )}

          {activeTab === 'community' && (
            <motion.div
              key="community"
              initial={{ opacity: 0, y: 14 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -14 }}
              transition={{ duration: 0.26, ease: [0.16, 1, 0.3, 1] }}
            >
              <ThreatIntelFeed
                reports={communityReports}
                setReports={setCommunityReports}
                onShowToast={showToast}
                onTriageDomain={handleTriageDomainFromIntel}
              />
            </motion.div>
          )}

          {activeTab === 'invariants' && (
            <motion.div
              key="invariants"
              initial={{ opacity: 0, y: 14 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -14 }}
              transition={{ duration: 0.26, ease: [0.16, 1, 0.3, 1] }}
            >
              <InvariantsExplorer
                onSelectScenario={handleSelectScenarioFromInvariants}
              />
            </motion.div>
          )}
        </AnimatePresence>
      </main>

      {/* Footer */}
      <Footer
        onSelectTab={setActiveTab}
        onOpenBackendModal={() => setIsBackendModalOpen(true)}
      />

      {/* FastAPI Specs Modal */}
      <BackendModal
        isOpen={isBackendModalOpen}
        onClose={() => setIsBackendModalOpen(false)}
        onShowToast={showToast}
      />

      {/* Toast Notification */}
      <Toast message={toastMessage} />
    </div>
  );
}
