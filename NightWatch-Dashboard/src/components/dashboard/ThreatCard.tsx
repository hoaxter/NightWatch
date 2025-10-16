import { AlertTriangle, Shield, Wifi, FileX, Bug, Lock } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

interface ThreatCardProps {
  type: "malware" | "network" | "files" | "patches" | "behavior" | "intrusion";
  count: number;
  severity: "low" | "medium" | "high" | "critical";
  trend?: "up" | "down" | "stable";
  recentActivity?: string;
}

const threatConfig = {
  malware: {
    icon: Bug,
    label: "Malware Detection",
    description: "Suspicious processes and files",
  },
  network: {
    icon: Wifi,
    label: "Network Anomalies", 
    description: "Unusual traffic patterns",
  },
  files: {
    icon: FileX,
    label: "File Integrity",
    description: "Unauthorized file changes",
  },
  patches: {
    icon: Shield,
    label: "Security Patches",
    description: "Missing critical updates",
  },
  behavior: {
    icon: AlertTriangle,
    label: "Behavior Analysis",
    description: "Anomalous system behavior",
  },
  intrusion: {
    icon: Lock,
    label: "Intrusion Attempts",
    description: "Unauthorized access attempts",
  },
};

const severityConfig = {
  low: { color: "text-success", bg: "bg-success/10", border: "border-success/20" },
  medium: { color: "text-warning", bg: "bg-warning/10", border: "border-warning/20" },
  high: { color: "text-warning", bg: "bg-warning/20", border: "border-warning/30" },
  critical: { color: "text-critical", bg: "bg-critical/10", border: "border-critical/20" },
};

export const ThreatCard = ({ type, count, severity, trend = "stable", recentActivity }: ThreatCardProps) => {
  const config = threatConfig[type];
  const severityStyle = severityConfig[severity];
  const Icon = config.icon;

  const getTrendIcon = () => {
    if (trend === "up") return "↗";
    if (trend === "down") return "↘";
    return "→";
  };

  return (
    <Card className={cn("shadow-card hover:shadow-glow transition-all duration-300", severityStyle.border)}>
      <CardContent className="p-6">
        <div className="flex items-start justify-between">
          <div className="flex items-center space-x-3">
            <div className={cn("p-3 rounded-lg", severityStyle.bg)}>
              <Icon className={cn("w-6 h-6", severityStyle.color)} />
            </div>
            <div>
              <h3 className="font-semibold text-card-foreground">{config.label}</h3>
              <p className="text-sm text-muted-foreground">{config.description}</p>
            </div>
          </div>
          <Badge 
            variant="outline" 
            className={cn("capitalize", severityStyle.color, severityStyle.bg, severityStyle.border)}
          >
            {severity}
          </Badge>
        </div>

        <div className="mt-4 flex items-end justify-between">
          <div>
            <p className="text-3xl font-bold text-card-foreground">{count}</p>
            <p className="text-sm text-muted-foreground flex items-center">
              <span className={cn(
                "mr-1",
                trend === "up" ? "text-critical" : trend === "down" ? "text-success" : "text-muted-foreground"
              )}>
                {getTrendIcon()}
              </span>
              {trend === "up" ? "Increasing" : trend === "down" ? "Decreasing" : "Stable"}
            </p>
          </div>
          {recentActivity && (
            <div className="text-right">
              <p className="text-xs text-muted-foreground">Last detected</p>
              <p className="text-sm font-medium text-card-foreground">{recentActivity}</p>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
};