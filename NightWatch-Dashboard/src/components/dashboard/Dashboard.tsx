import { useState } from "react";
import { Sidebar } from "./Sidebar";
import { StatsOverview } from "./StatsOverview";
import { ThreatCard } from "./ThreatCard";
import { ThreatChart } from "./ThreatChart";
import { AlertFeed } from "./AlertFeed";
import { ThreatDetection } from "./ThreatDetection";
import { NetworkMonitor } from "./NetworkMonitor";
import { FileIntegrity } from "./FileIntegrity";
import { Analytics } from "./Analytics";
import { Endpoints } from "./Endpoints";
import { EventLogs } from "./EventLogs";

export const Dashboard = () => {
  const [activeSection, setActiveSection] = useState("overview");

  const threatCategories = [
    {
      type: "malware" as const,
      count: 23,
      severity: "high" as const,
      trend: "up" as const,
      recentActivity: "5 min ago"
    },
    {
      type: "network" as const,
      count: 17,
      severity: "medium" as const,
      trend: "stable" as const,
      recentActivity: "12 min ago"
    },
    {
      type: "files" as const,
      count: 8,
      severity: "low" as const,
      trend: "down" as const,
      recentActivity: "1 hour ago"
    },
    {
      type: "patches" as const,
      count: 45,
      severity: "critical" as const,
      trend: "up" as const,
      recentActivity: "2 hours ago"
    },
    {
      type: "behavior" as const,
      count: 12,
      severity: "medium" as const,
      trend: "stable" as const,
      recentActivity: "30 min ago"
    },
    {
      type: "intrusion" as const,
      count: 6,
      severity: "high" as const,
      trend: "down" as const,
      recentActivity: "45 min ago"
    }
  ];

  const renderContent = () => {
    switch (activeSection) {
      case "threats":
        return <ThreatDetection />;
      case "network":
        return <NetworkMonitor />;
      case "files":
        return <FileIntegrity />;
      case "analytics":
        return <Analytics />;
      case "endpoints":
        return <Endpoints />;
      case "logs":
        return <EventLogs />;
      default:
        return (
          <div className="space-y-8">
            {/* Header */}
            <div className="flex items-center justify-between">
              <div>
                <h1 className="text-3xl font-bold text-foreground">Security Overview</h1>
                <p className="text-muted-foreground">Real-time endpoint detection and response monitoring</p>
              </div>
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 bg-success rounded-full animate-pulse"></div>
                <span className="text-sm font-medium text-foreground">System Online</span>
              </div>
            </div>

            {/* Stats Overview */}
            <StatsOverview />

            {/* Threat Categories Grid */}
            <div>
              <h2 className="text-xl font-semibold text-foreground mb-6">Threat Categories</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {threatCategories.map((threat, index) => (
                  <ThreatCard key={index} {...threat} />
                ))}
              </div>
            </div>

            {/* Charts and Alert Feed */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
              <div className="lg:col-span-2">
                <h2 className="text-xl font-semibold text-foreground mb-6">Analytics</h2>
                <ThreatChart />
              </div>
              <div className="lg:col-span-1">
                <AlertFeed />
              </div>
            </div>
          </div>
        );
    }
  };

  return (
    <div className="flex h-screen bg-gradient-dashboard">
      <Sidebar activeSection={activeSection} onSectionChange={setActiveSection} />
      
      <main className="flex-1 overflow-auto">
        <div className="p-8">
          {renderContent()}
        </div>
      </main>
    </div>
  );
};