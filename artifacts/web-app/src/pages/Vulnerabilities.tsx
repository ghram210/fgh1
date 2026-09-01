import { useState } from "react";
import AppSidebar from "@/components/AppSidebar";
import TopBar from "@/components/TopBar";
import VulnerabilitiesTab from "@/components/VulnerabilitiesTab";
import ReportsTab from "@/components/ReportsTab";
import { Download, Settings2, FileText } from "lucide-react";

const Vulnerabilities = () => {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [activeTab, setActiveTab] = useState<"vulnerabilities" | "reports">("vulnerabilities");

  return (
    <div className="flex h-screen overflow-hidden">
      <AppSidebar
        collapsed={sidebarCollapsed}
        onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
        activePage="vulnerabilities"
      />
      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar />
        <main className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Header */}
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold text-foreground">Vulnerability Management</h1>
              <p className="text-sm text-primary mt-1">Vulnerabilities found on your infrastructure</p>
            </div>
            <button className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium hover:bg-primary/90 transition-colors">
              <Download className="w-4 h-4" />
              Export Report
            </button>
          </div>

          {/* Tabs */}
          <div className="flex gap-1">
            <button
              onClick={() => setActiveTab("vulnerabilities")}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                activeTab === "vulnerabilities"
                  ? "bg-primary text-primary-foreground"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              <Settings2 className="w-4 h-4" />
              Vulnerabilities
            </button>
            <button
              onClick={() => setActiveTab("reports")}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                activeTab === "reports"
                  ? "bg-primary text-primary-foreground"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              <FileText className="w-4 h-4" />
              Reports
            </button>
          </div>

          {activeTab === "vulnerabilities" ? <VulnerabilitiesTab /> : <ReportsTab />}
        </main>
      </div>
    </div>
  );
};

export default Vulnerabilities;
