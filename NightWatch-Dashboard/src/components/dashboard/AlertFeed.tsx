import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { AlertTriangle, Shield, Wifi, FileX, Clock, ChevronRight } from "lucide-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";

interface Alert {
  id: string;
  type: "malware" | "network" | "files" | "intrusion";
  severity: "low" | "medium" | "high" | "critical";
  title: string;
  description: string;
  timestamp: string;
  endpoint: string;
  status: "new" | "investigating" | "resolved";
}

const mockAlerts: Alert[] = [
  {
    id: "1",
    type: "malware",
    severity: "critical",
    title: "Suspicious Process Detected",
    description: "PowerShell execution from temp directory",
    timestamp: "2 min ago",
    endpoint: "DESKTOP-ABC123",
    status: "new"
  },
  {
    id: "2", 
    type: "network",
    severity: "high",
    title: "Unusual Outbound Connection",
    description: "Connection to suspicious IP 192.168.1.100",
    timestamp: "15 min ago", 
    endpoint: "SERVER-DEF456",
    status: "investigating"
  },
  {
    id: "3",
    type: "files",
    severity: "medium", 
    title: "File Integrity Violation",
    description: "Critical system file modified",
    timestamp: "1 hour ago",
    endpoint: "WORKSTATION-GHI789", 
    status: "resolved"
  },
  {
    id: "4",
    type: "intrusion",
    severity: "high",
    title: "Failed Login Attempts",
    description: "Multiple failed administrator logins", 
    timestamp: "2 hours ago",
    endpoint: "DC-PRIMARY",
    status: "investigating"
  },
  {
    id: "5",
    type: "malware",
    severity: "medium",
    title: "Suspicious Registry Modification", 
    description: "Autorun registry key added",
    timestamp: "3 hours ago",
    endpoint: "LAPTOP-JKL012",
    status: "resolved"
  }
];

const getAlertIcon = (type: Alert["type"]) => {
  switch (type) {
    case "malware": return AlertTriangle;
    case "network": return Wifi;
    case "files": return FileX;
    case "intrusion": return Shield;
    default: return AlertTriangle;
  }
};

const getSeverityColor = (severity: Alert["severity"]) => {
  switch (severity) {
    case "critical": return "text-critical bg-critical/10 border-critical/20";
    case "high": return "text-warning bg-warning/10 border-warning/20";
    case "medium": return "text-info bg-info/10 border-info/20";
    case "low": return "text-success bg-success/10 border-success/20";
    default: return "text-muted-foreground bg-muted/10 border-border";
  }
};

const getStatusColor = (status: Alert["status"]) => {
  switch (status) {
    case "new": return "text-critical bg-critical/10";
    case "investigating": return "text-warning bg-warning/10";
    case "resolved": return "text-success bg-success/10";
    default: return "text-muted-foreground bg-muted/10";
  }
};

export const AlertFeed = () => {
  return (
    <Card className="shadow-card h-full">
      <CardHeader className="pb-4">
        <CardTitle className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <div className="w-2 h-2 bg-primary rounded-full"></div>
            <span>Live Alert Feed</span>
          </div>
          <Badge variant="outline" className="text-xs">
            {mockAlerts.filter(a => a.status === "new").length} New
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        <ScrollArea className="h-[600px]">
          <div className="space-y-1 p-6 pt-0">
            {mockAlerts.map((alert) => {
              const Icon = getAlertIcon(alert.type);
              return (
                <div
                  key={alert.id}
                  className="flex items-start space-x-3 p-4 rounded-lg border border-border hover:bg-accent/50 transition-all duration-200 cursor-pointer group"
                >
                  <div className={cn("p-2 rounded-lg flex-shrink-0", getSeverityColor(alert.severity))}>
                    <Icon className="w-4 h-4" />
                  </div>
                  
                  <div className="flex-1 min-w-0">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <p className="font-medium text-card-foreground text-sm">{alert.title}</p>
                        <p className="text-xs text-muted-foreground mt-1">{alert.description}</p>
                        <div className="flex items-center space-x-3 mt-2">
                          <span className="text-xs text-muted-foreground flex items-center">
                            <Clock className="w-3 h-3 mr-1" />
                            {alert.timestamp}
                          </span>
                          <span className="text-xs font-medium text-card-foreground">
                            {alert.endpoint}
                          </span>
                        </div>
                      </div>
                      <div className="flex flex-col items-end space-y-2 ml-4">
                        <Badge 
                          variant="outline" 
                          className={cn("text-xs capitalize", getSeverityColor(alert.severity))}
                        >
                          {alert.severity}
                        </Badge>
                        <Badge 
                          variant="secondary" 
                          className={cn("text-xs capitalize", getStatusColor(alert.status))}
                        >
                          {alert.status}
                        </Badge>
                      </div>
                    </div>
                  </div>
                  
                  <ChevronRight className="w-4 h-4 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0" />
                </div>
              );
            })}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
};