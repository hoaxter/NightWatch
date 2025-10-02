import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Clock, Search, Filter, Download, AlertTriangle, Info, CheckCircle, XCircle } from "lucide-react";

const eventLogs = [
  {
    id: "LOG-001",
    timestamp: "2024-01-21 14:32:15",
    level: "critical",
    category: "Threat Detection",
    endpoint: "WS-ADMIN-01",
    user: "admin@company.com",
    event: "Malicious PowerShell execution blocked",
    details: "Encoded PowerShell command attempting to download payload from external source",
    source: "Process Monitor"
  },
  {
    id: "LOG-002",
    timestamp: "2024-01-21 14:28:42",
    level: "warning",
    category: "File Integrity",
    endpoint: "LX-SERVER-03",
    user: "root",
    event: "System file modification detected",
    details: "/etc/passwd file modified - user account changes detected",
    source: "File Integrity Monitor"
  },
  {
    id: "LOG-003",
    timestamp: "2024-01-21 14:25:18",
    level: "info",
    category: "Network Activity",
    endpoint: "WS-USER-15",
    user: "john.doe@company.com",
    event: "Outbound connection established",
    details: "Connection to legitimate service api.microsoft.com:443",
    source: "Network Monitor"
  },
  {
    id: "LOG-004",
    timestamp: "2024-01-21 14:22:03",
    level: "high",
    category: "Behavior Analysis",
    endpoint: "WS-DEV-05",
    user: "jane.smith@company.com",
    event: "Suspicious process injection detected",
    details: "Process attempting to inject code into system process - blocked",
    source: "Behavior Monitor"
  },
  {
    id: "LOG-005",
    timestamp: "2024-01-21 14:18:37",
    level: "info",
    category: "System",
    endpoint: "WS-ADMIN-01",
    user: "system",
    event: "Agent status update",
    details: "NightWatch agent heartbeat - all systems operational",
    source: "Agent Communication"
  },
  {
    id: "LOG-006",
    timestamp: "2024-01-21 14:15:22",
    level: "medium",
    category: "Network Activity",
    endpoint: "WS-USER-07",
    user: "sales@company.com",
    event: "Blocked connection to suspicious domain",
    details: "Connection attempt to newly registered domain blocked by reputation filter",
    source: "Network Monitor"
  }
];

const logStats = [
  { label: "Total Events", value: "12,847", icon: Clock },
  { label: "Critical Events", value: "23", icon: AlertTriangle },
  { label: "Blocked Threats", value: "156", icon: XCircle },
  { label: "System Events", value: "1,247", icon: Info }
];

const getLevelColor = (level: string) => {
  switch (level) {
    case "critical": return "bg-critical text-critical-foreground";
    case "high": return "bg-warning text-warning-foreground";
    case "warning": return "bg-warning text-warning-foreground";
    case "medium": return "bg-info text-info-foreground";
    case "info": return "bg-muted text-muted-foreground";
    case "low": return "bg-success text-success-foreground";
    default: return "bg-muted text-muted-foreground";
  }
};

const getLevelIcon = (level: string) => {
  switch (level) {
    case "critical": return <AlertTriangle className="w-4 h-4 text-critical" />;
    case "high": return <AlertTriangle className="w-4 h-4 text-warning" />;
    case "warning": return <AlertTriangle className="w-4 h-4 text-warning" />;
    case "medium": return <Info className="w-4 h-4 text-info" />;
    case "info": return <CheckCircle className="w-4 h-4 text-success" />;
    case "low": return <CheckCircle className="w-4 h-4 text-success" />;
    default: return <Info className="w-4 h-4 text-muted-foreground" />;
  }
};

const getCategoryColor = (category: string) => {
  switch (category) {
    case "Threat Detection": return "border-critical text-critical";
    case "File Integrity": return "border-warning text-warning";
    case "Network Activity": return "border-info text-info";
    case "Behavior Analysis": return "border-warning text-warning";
    case "System": return "border-success text-success";
    default: return "border-muted text-muted-foreground";
  }
};

export const EventLogs = () => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Event Logs</h1>
          <p className="text-muted-foreground">Comprehensive security event monitoring and analysis</p>
        </div>
        <div className="flex items-center space-x-2">
          <Button variant="outline">
            <Download className="w-4 h-4 mr-2" />
            Export Logs
          </Button>
          <Button variant="outline">
            <Filter className="w-4 h-4 mr-2" />
            Advanced Filter
          </Button>
        </div>
      </div>

      {/* Log Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {logStats.map((stat, index) => {
          const Icon = stat.icon;
          return (
            <Card key={index} className="shadow-card">
              <CardContent className="p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">{stat.label}</p>
                    <p className="text-2xl font-bold text-foreground">{stat.value}</p>
                  </div>
                  <Icon className="w-8 h-8 text-primary" />
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Search and Filter */}
      <Card className="shadow-card">
        <CardContent className="p-6">
          <div className="flex items-center space-x-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
              <Input 
                placeholder="Search logs by event, endpoint, user, or details..." 
                className="pl-10"
              />
            </div>
            <Button variant="outline">
              <Filter className="w-4 h-4 mr-2" />
              Date Range
            </Button>
            <Button variant="outline">
              <Filter className="w-4 h-4 mr-2" />
              Severity Level
            </Button>
          </div>
        </CardContent>
      </Card>

      <Tabs defaultValue="all" className="w-full">
        <TabsList className="grid w-full grid-cols-6">
          <TabsTrigger value="all">All Events</TabsTrigger>
          <TabsTrigger value="critical">Critical</TabsTrigger>
          <TabsTrigger value="threats">Threats</TabsTrigger>
          <TabsTrigger value="network">Network</TabsTrigger>
          <TabsTrigger value="files">Files</TabsTrigger>
          <TabsTrigger value="system">System</TabsTrigger>
        </TabsList>

        <TabsContent value="all" className="space-y-4">
          {eventLogs.map((log) => (
            <Card key={log.id} className="shadow-card">
              <CardContent className="p-6">
                <div className="flex items-start justify-between">
                  <div className="flex items-start space-x-4">
                    {getLevelIcon(log.level)}
                    <div className="flex-1">
                      <div className="flex items-center space-x-3 mb-2">
                        <h3 className="font-semibold text-foreground">{log.event}</h3>
                        <Badge className={getLevelColor(log.level)}>
                          {log.level.toUpperCase()}
                        </Badge>
                        <Badge variant="outline" className={getCategoryColor(log.category)}>
                          {log.category}
                        </Badge>
                      </div>
                      <p className="text-sm text-muted-foreground mb-2">{log.details}</p>
                      <div className="flex items-center space-x-4 text-sm text-muted-foreground">
                        <span><strong>Endpoint:</strong> {log.endpoint}</span>
                        <span><strong>User:</strong> {log.user}</span>
                        <span><strong>Source:</strong> {log.source}</span>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center space-x-4">
                    <div className="text-right">
                      <p className="text-sm font-medium text-foreground">
                        <Clock className="w-4 h-4 inline mr-1" />
                        {log.timestamp}
                      </p>
                      <p className="text-xs text-muted-foreground">ID: {log.id}</p>
                    </div>
                    <Button size="sm" variant="outline">Details</Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </TabsContent>

        <TabsContent value="critical">
          <Card className="shadow-card">
            <CardContent className="p-12 text-center">
              <AlertTriangle className="w-16 h-16 text-critical mx-auto mb-4" />
              <h3 className="text-lg font-medium text-foreground">Critical Events</h3>
              <p className="text-muted-foreground">Showing only critical security events</p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="threats">
          <Card className="shadow-card">
            <CardContent className="p-12 text-center">
              <AlertTriangle className="w-16 h-16 text-warning mx-auto mb-4" />
              <h3 className="text-lg font-medium text-foreground">Threat Detection Events</h3>
              <p className="text-muted-foreground">Showing threat detection and response events</p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="network">
          <Card className="shadow-card">
            <CardContent className="p-12 text-center">
              <Info className="w-16 h-16 text-info mx-auto mb-4" />
              <h3 className="text-lg font-medium text-foreground">Network Activity Events</h3>
              <p className="text-muted-foreground">Showing network monitoring and security events</p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="files">
          <Card className="shadow-card">
            <CardContent className="p-12 text-center">
              <CheckCircle className="w-16 h-16 text-success mx-auto mb-4" />
              <h3 className="text-lg font-medium text-foreground">File Integrity Events</h3>
              <p className="text-muted-foreground">Showing file system monitoring events</p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="system">
          <Card className="shadow-card">
            <CardContent className="p-12 text-center">
              <Clock className="w-16 h-16 text-muted-foreground mx-auto mb-4" />
              <h3 className="text-lg font-medium text-foreground">System Events</h3>
              <p className="text-muted-foreground">Showing system status and operational events</p>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};