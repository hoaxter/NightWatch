import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { FileX, AlertTriangle, CheckCircle, Clock, File, Folder, Hash } from "lucide-react";

const fileChanges = [
  {
    id: "FI-001",
    path: "C:\\Windows\\System32\\kernel32.dll",
    action: "modified",
    severity: "critical",
    endpoint: "WS-ADMIN-01",
    timestamp: "5 minutes ago",
    oldHash: "sha256:a1b2c3d4...",
    newHash: "sha256:e5f6g7h8...",
    status: "investigating"
  },
  {
    id: "FI-002",
    path: "/etc/passwd",
    action: "modified",
    severity: "high",
    endpoint: "LX-SERVER-03",
    timestamp: "12 minutes ago",
    oldHash: "sha256:x9y8z7w6...",
    newHash: "sha256:v5u4t3s2...",
    status: "blocked"
  },
  {
    id: "FI-003",
    path: "C:\\Program Files\\CriticalApp\\config.xml",
    action: "deleted",
    severity: "medium",
    endpoint: "WS-USER-07",
    timestamp: "25 minutes ago",
    oldHash: "sha256:m1n2o3p4...",
    newHash: null,
    status: "restored"
  }
];

const monitoredDirectories = [
  {
    path: "C:\\Windows\\System32",
    files: 1247,
    status: "protected",
    lastScan: "2 minutes ago",
    changes: 1
  },
  {
    path: "/etc",
    files: 156,
    status: "protected", 
    lastScan: "5 minutes ago",
    changes: 1
  },
  {
    path: "C:\\Program Files",
    files: 8932,
    status: "monitoring",
    lastScan: "8 minutes ago",
    changes: 3
  },
  {
    path: "/var/log",
    files: 243,
    status: "monitoring",
    lastScan: "10 minutes ago", 
    changes: 0
  }
];

const integrityStats = [
  { label: "Files Monitored", value: "10,578", icon: File },
  { label: "Changes Detected", value: "5", icon: AlertTriangle },
  { label: "Protected Directories", value: "12", icon: Folder },
  { label: "Hash Verifications", value: "1,247", icon: Hash }
];

const getSeverityColor = (severity: string) => {
  switch (severity) {
    case "critical": return "bg-critical text-critical-foreground";
    case "high": return "bg-warning text-warning-foreground";
    case "medium": return "bg-info text-info-foreground";
    case "low": return "bg-success text-success-foreground";
    default: return "bg-muted text-muted-foreground";
  }
};

const getStatusIcon = (status: string) => {
  switch (status) {
    case "investigating": return <Clock className="w-4 h-4 text-warning" />;
    case "blocked": return <AlertTriangle className="w-4 h-4 text-critical" />;
    case "restored": return <CheckCircle className="w-4 h-4 text-success" />;
    default: return <FileX className="w-4 h-4 text-muted-foreground" />;
  }
};

const getActionColor = (action: string) => {
  switch (action) {
    case "modified": return "text-warning";
    case "deleted": return "text-critical";
    case "created": return "text-info";
    default: return "text-muted-foreground";
  }
};

export const FileIntegrity = () => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">File Integrity Monitoring</h1>
          <p className="text-muted-foreground">Real-time file system monitoring and protection</p>
        </div>
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 bg-success rounded-full animate-pulse"></div>
            <span className="text-sm font-medium text-foreground">FIM Active</span>
          </div>
          <Button variant="outline">
            <FileX className="w-4 h-4 mr-2" />
            Full Baseline Scan
          </Button>
        </div>
      </div>

      {/* Stats Overview */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {integrityStats.map((stat, index) => {
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

      <Tabs defaultValue="changes" className="w-full">
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="changes">Recent Changes</TabsTrigger>
          <TabsTrigger value="directories">Monitored Directories</TabsTrigger>
        </TabsList>

        <TabsContent value="changes" className="space-y-4">
          {fileChanges.map((change) => (
            <Card key={change.id} className="shadow-card">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    {getStatusIcon(change.status)}
                    <div>
                      <CardTitle className="text-lg flex items-center space-x-2">
                        <span className={`capitalize ${getActionColor(change.action)}`}>
                          {change.action}
                        </span>
                        <span>File</span>
                      </CardTitle>
                      <CardDescription>{change.path}</CardDescription>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Badge className={getSeverityColor(change.severity)}>
                      {change.severity.toUpperCase()}
                    </Badge>
                    <span className="text-sm text-muted-foreground">{change.timestamp}</span>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <p className="text-sm text-muted-foreground">
                    <strong>Endpoint:</strong> {change.endpoint}
                  </p>
                  {change.oldHash && (
                    <p className="text-sm text-muted-foreground">
                      <strong>Previous Hash:</strong> {change.oldHash}
                    </p>
                  )}
                  {change.newHash && (
                    <p className="text-sm text-muted-foreground">
                      <strong>Current Hash:</strong> {change.newHash}
                    </p>
                  )}
                </div>
                <div className="flex space-x-2 mt-4">
                  <Button size="sm" variant="default">Investigate</Button>
                  <Button size="sm" variant="outline">Restore Backup</Button>
                  <Button size="sm" variant="destructive">Quarantine</Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </TabsContent>

        <TabsContent value="directories" className="space-y-4">
          {monitoredDirectories.map((directory, index) => (
            <Card key={index} className="shadow-card">
              <CardContent className="p-6">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-4">
                    <Folder className="w-8 h-8 text-primary" />
                    <div>
                      <h3 className="font-semibold text-foreground">{directory.path}</h3>
                      <p className="text-sm text-muted-foreground">
                        {directory.files} files • Last scan: {directory.lastScan}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-4">
                    <div className="text-right">
                      <Badge variant={directory.status === "protected" ? "default" : "outline"}>
                        {directory.status.toUpperCase()}
                      </Badge>
                      {directory.changes > 0 && (
                        <p className="text-sm text-warning mt-1">
                          {directory.changes} change{directory.changes > 1 ? 's' : ''} detected
                        </p>
                      )}
                    </div>
                    <Button size="sm" variant="outline">Configure</Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </TabsContent>
      </Tabs>
    </div>
  );
};