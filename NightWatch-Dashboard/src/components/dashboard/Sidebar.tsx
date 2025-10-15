import { Shield, AlertTriangle, Network, FileX, Settings, Home, BarChart3, Users, Clock } from "lucide-react";
import { cn } from "@/lib/utils";

interface SidebarProps {
  activeSection: string;
  onSectionChange: (section: string) => void;
}

const navigationItems = [
  { id: "overview", label: "Overview", icon: Home },
  { id: "threats", label: "Threat Detection", icon: Shield },
  { id: "network", label: "Network Monitor", icon: Network },
  { id: "files", label: "File Integrity", icon: FileX },
  { id: "analytics", label: "Analytics", icon: BarChart3 },
  { id: "endpoints", label: "Endpoints", icon: Users },
  { id: "logs", label: "Event Logs", icon: Clock },
  { id: "settings", label: "Settings", icon: Settings },
];

export const Sidebar = ({ activeSection, onSectionChange }: SidebarProps) => {
  return (
    <div className="w-64 bg-sidebar border-r border-sidebar-border h-screen flex flex-col">
      {/* Logo */}
      <div className="p-6 border-b border-sidebar-border">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 bg-gradient-primary rounded-lg flex items-center justify-center shadow-glow">
            <Shield className="w-6 h-6 text-primary-foreground" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-sidebar-foreground">NightWatch</h1>
            <p className="text-sm text-sidebar-foreground/60">EDR Dashboard</p>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-4">
        <div className="space-y-2">
          {navigationItems.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.id}
                onClick={() => onSectionChange(item.id)}
                className={cn(
                  "w-full flex items-center space-x-3 px-4 py-3 rounded-lg text-left transition-all duration-200",
                  activeSection === item.id
                    ? "bg-sidebar-accent text-sidebar-primary border border-sidebar-primary/20 shadow-glow"
                    : "text-sidebar-foreground/80 hover:bg-sidebar-accent hover:text-sidebar-foreground"
                )}
              >
                <Icon className="w-5 h-5" />
                <span className="font-medium">{item.label}</span>
              </button>
            );
          })}
        </div>
      </nav>

      {/* Status Indicator */}
      <div className="p-4 border-t border-sidebar-border">
        <div className="flex items-center space-x-3 px-4 py-3 bg-sidebar-accent rounded-lg">
          <div className="w-3 h-3 bg-success rounded-full animate-pulse"></div>
          <div>
            <p className="text-sm font-medium text-sidebar-foreground">System Status</p>
            <p className="text-xs text-sidebar-foreground/60">All agents online</p>
          </div>
        </div>
      </div>
    </div>
  );
};