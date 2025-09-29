import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Shield, AlertTriangle, CheckCircle, XCircle, Clock } from "lucide-react";

const activeThreatData = [
  {
    id: "THR-001",
    name: "Suspicious PowerShell Execution",
    severity: "critical",
    status: "active",
    endpoint: "WS-ADMIN-01",
    detectedAt: "2 minutes ago",
    description: "Encoded PowerShell command detected attempting to download payload"
  },
  {
    id: "THR-002", 
    name: "Unauthorized Registry Modification",
    severity: "high",
    status: "investigating",
    endpoint: "WS-USER-15",
    detectedAt: "8 minutes ago",
    description: "Registry key modification in HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
  },
  {
    id: "THR-003",
    name: "Network Connection to Suspicious IP",
    severity: "medium",
    status: "contained",
    endpoint: "WS-DEV-03",
    detectedAt: "15 minutes ago",
    description: "Outbound connection to known malicious IP 192.168.1.100"
  }
];

const resolvedThreatData = [
  {
    id: "THR-004",
    name: "Malware Signature Detected",
    severity: "high",
    status: "resolved",
    endpoint: "WS-USER-08",
    resolvedAt: "1 hour ago",
    description: "Trojan.Generic.KD.12345 quarantined successfully"
  },
  {
    id: "THR-005",
    name: "Suspicious File Execution",
    severity: "medium", 
    status: "resolved",
    endpoint: "WS-ADMIN-02",
    resolvedAt: "3 hours ago",
    description: "Executable from temp directory blocked and removed"
  }
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
    case "active": return <AlertTriangle className="w-4 h-4 text-critical" />;
    case "investigating": return <Clock className="w-4 h-4 text-warning" />;
    case "contained": return <Shield className="w-4 h-4 text-info" />;
    case "resolved": return <CheckCircle className="w-4 h-4 text-success" />;
    default: return <XCircle className="w-4 h-4 text-muted-foreground" />;
  }
};

export const ThreatDetection = () => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Threat Detection</h1>
          <p className="text-muted-foreground">Real-time threat monitoring and response</p>
        </div>
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 bg-critical rounded-full animate-pulse"></div>
            <span className="text-sm font-medium text-foreground">3 Active Threats</span>
          </div>
          <Button variant="outline">
            <Shield className="w-4 h-4 mr-2" />
            Run Full Scan
          </Button>
        </div>
      </div>

      <Tabs defaultValue="active" className="w-full">
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="active">Active Threats</TabsTrigger>
          <TabsTrigger value="resolved">Resolved Threats</TabsTrigger>
        </TabsList>

        <TabsContent value="active" className="space-y-4">
          {activeThreatData.map((threat) => (
            <Card key={threat.id} className="shadow-card">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    {getStatusIcon(threat.status)}
                    <div>
                      <CardTitle className="text-lg">{threat.name}</CardTitle>
                      <CardDescription>ID: {threat.id} • {threat.endpoint}</CardDescription>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Badge className={getSeverityColor(threat.severity)}>
                      {threat.severity.toUpperCase()}
                    </Badge>
                    <span className="text-sm text-muted-foreground">{threat.detectedAt}</span>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground mb-4">{threat.description}</p>
                <div className="flex space-x-2">
                  <Button size="sm" variant="default">Investigate</Button>
                  <Button size="sm" variant="outline">Contain</Button>
                  <Button size="sm" variant="destructive">Block</Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </TabsContent>

        <TabsContent value="resolved" className="space-y-4">
          {resolvedThreatData.map((threat) => (
            <Card key={threat.id} className="shadow-card opacity-75">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    {getStatusIcon(threat.status)}
                    <div>
                      <CardTitle className="text-lg">{threat.name}</CardTitle>
                      <CardDescription>ID: {threat.id} • {threat.endpoint}</CardDescription>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Badge className={getSeverityColor(threat.severity)}>
                      {threat.severity.toUpperCase()}
                    </Badge>
                    <span className="text-sm text-muted-foreground">Resolved {threat.resolvedAt}</span>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground">{threat.description}</p>
              </CardContent>
            </Card>
          ))}
        </TabsContent>
      </Tabs>
    </div>
  );
};