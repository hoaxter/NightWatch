import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Network, Globe, Shield, AlertTriangle, TrendingUp, TrendingDown } from "lucide-react";
import { ResponsiveContainer, LineChart, Line, XAxis, YAxis, Tooltip, AreaChart, Area } from "recharts";

const networkTrafficData = [
  { time: "00:00", inbound: 1200, outbound: 800, threats: 2 },
  { time: "04:00", inbound: 1800, outbound: 1200, threats: 5 },
  { time: "08:00", inbound: 3200, outbound: 2400, threats: 12 },
  { time: "12:00", inbound: 2800, outbound: 2100, threats: 8 },
  { time: "16:00", inbound: 4100, outbound: 3200, threats: 15 },
  { time: "20:00", inbound: 3500, outbound: 2800, threats: 10 },
];

const suspiciousConnections = [
  {
    id: "NC-001",
    endpoint: "WS-USER-12",
    destination: "malicious-site.com (192.168.1.100)",
    port: "8080",
    protocol: "HTTP",
    risk: "high",
    blocked: true,
    timestamp: "3 minutes ago"
  },
  {
    id: "NC-002", 
    endpoint: "WS-DEV-05",
    destination: "suspicious-domain.net (10.0.0.50)",
    port: "22", 
    protocol: "SSH",
    risk: "medium",
    blocked: false,
    timestamp: "7 minutes ago"
  },
  {
    id: "NC-003",
    endpoint: "WS-ADMIN-01",
    destination: "unknown-server.org (172.16.0.25)",
    port: "443",
    protocol: "HTTPS",
    risk: "low",
    blocked: false,
    timestamp: "12 minutes ago"
  }
];

const networkStats = [
  { label: "Total Connections", value: "15,247", change: "+12%", trending: "up" },
  { label: "Blocked Threats", value: "23", change: "-8%", trending: "down" },
  { label: "Bandwidth Usage", value: "2.4 GB", change: "+5%", trending: "up" },
  { label: "Active Endpoints", value: "156", change: "0%", trending: "stable" }
];

const getRiskColor = (risk: string) => {
  switch (risk) {
    case "high": return "bg-critical text-critical-foreground";
    case "medium": return "bg-warning text-warning-foreground";
    case "low": return "bg-success text-success-foreground";
    default: return "bg-muted text-muted-foreground";
  }
};

export const NetworkMonitor = () => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Network Monitor</h1>
          <p className="text-muted-foreground">Real-time network activity and threat detection</p>
        </div>
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 bg-success rounded-full animate-pulse"></div>
            <span className="text-sm font-medium text-foreground">Network Monitoring Active</span>
          </div>
          <Button variant="outline">
            <Network className="w-4 h-4 mr-2" />
            Configure Filters
          </Button>
        </div>
      </div>

      {/* Network Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {networkStats.map((stat, index) => (
          <Card key={index} className="shadow-card">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">{stat.label}</p>
                  <p className="text-2xl font-bold text-foreground">{stat.value}</p>
                </div>
                <div className="flex items-center space-x-1">
                  {stat.trending === "up" && <TrendingUp className="w-4 h-4 text-success" />}
                  {stat.trending === "down" && <TrendingDown className="w-4 h-4 text-critical" />}
                  <span className={`text-sm font-medium ${
                    stat.change.startsWith('+') ? 'text-success' : 
                    stat.change.startsWith('-') ? 'text-critical' : 'text-muted-foreground'
                  }`}>
                    {stat.change}
                  </span>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Network Traffic Chart */}
      <Card className="shadow-card">
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Globe className="w-5 h-5 text-primary" />
            <span>Network Traffic Analysis</span>
          </CardTitle>
          <CardDescription>Real-time network traffic and threat detection over the last 24 hours</CardDescription>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={networkTrafficData}>
              <XAxis dataKey="time" stroke="hsl(var(--muted-foreground))" />
              <YAxis stroke="hsl(var(--muted-foreground))" />
              <Tooltip 
                contentStyle={{
                  backgroundColor: "hsl(var(--card))",
                  border: "1px solid hsl(var(--border))",
                  borderRadius: "8px"
                }}
              />
              <Line type="monotone" dataKey="inbound" stroke="hsl(var(--info))" strokeWidth={2} name="Inbound (MB)" />
              <Line type="monotone" dataKey="outbound" stroke="hsl(var(--success))" strokeWidth={2} name="Outbound (MB)" />
              <Line type="monotone" dataKey="threats" stroke="hsl(var(--critical))" strokeWidth={2} name="Threats Detected" />
            </LineChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      {/* Suspicious Connections */}
      <Card className="shadow-card">
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Shield className="w-5 h-5 text-primary" />
            <span>Suspicious Network Connections</span>
          </CardTitle>
          <CardDescription>Recent network connections flagged for review</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {suspiciousConnections.map((connection) => (
              <div key={connection.id} className="flex items-center justify-between p-4 border border-border rounded-lg">
                <div className="flex items-center space-x-4">
                  <AlertTriangle className={`w-5 h-5 ${
                    connection.risk === 'high' ? 'text-critical' : 
                    connection.risk === 'medium' ? 'text-warning' : 'text-info'
                  }`} />
                  <div>
                    <p className="font-medium text-foreground">{connection.endpoint}</p>
                    <p className="text-sm text-muted-foreground">
                      → {connection.destination} : {connection.port} ({connection.protocol})
                    </p>
                  </div>
                </div>
                <div className="flex items-center space-x-3">
                  <Badge className={getRiskColor(connection.risk)}>
                    {connection.risk.toUpperCase()}
                  </Badge>
                  {connection.blocked && (
                    <Badge variant="outline" className="text-critical border-critical">
                      BLOCKED
                    </Badge>
                  )}
                  <span className="text-sm text-muted-foreground">{connection.timestamp}</span>
                  <Button size="sm" variant="outline">Investigate</Button>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};