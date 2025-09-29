import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import { Users, Monitor, Smartphone, Server, CheckCircle, AlertTriangle, XCircle, Search, Filter, RefreshCw } from "lucide-react";

const endpointData = [
  {
    id: "EP-001",
    name: "WS-ADMIN-01",
    type: "Windows Workstation",
    user: "admin@company.com",
    ip: "192.168.1.101",
    status: "online",
    lastSeen: "Active now",
    threats: 2,
    version: "Agent v2.1.3",
    os: "Windows 11 Pro"
  },
  {
    id: "EP-002", 
    name: "WS-USER-15",
    type: "Windows Workstation",
    user: "john.doe@company.com",
    ip: "192.168.1.115",
    status: "online",
    lastSeen: "2 minutes ago",
    threats: 0,
    version: "Agent v2.1.3",
    os: "Windows 10 Pro"
  },
  {
    id: "EP-003",
    name: "LX-SERVER-03",
    type: "Linux Server",
    user: "root",
    ip: "192.168.1.203",
    status: "online",
    lastSeen: "5 minutes ago",
    threats: 1,
    version: "Agent v2.1.2",
    os: "Ubuntu 22.04 LTS"
  },
  {
    id: "EP-004",
    name: "WS-DEV-05",
    type: "macOS Workstation",
    user: "jane.smith@company.com",
    ip: "192.168.1.105",
    status: "offline",
    lastSeen: "2 hours ago",
    threats: 0,
    version: "Agent v2.1.1",
    os: "macOS Monterey 12.6"
  },
  {
    id: "EP-005",
    name: "MB-SALES-07",
    type: "Mobile Device",
    user: "sales@company.com", 
    ip: "192.168.1.207",
    status: "warning",
    lastSeen: "30 minutes ago",
    threats: 0,
    version: "Agent v2.0.8",
    os: "Android 13"
  }
];

const endpointStats = [
  { label: "Total Endpoints", value: "247", icon: Users, status: "success" },
  { label: "Online", value: "234", icon: CheckCircle, status: "success" },
  { label: "Offline", value: "8", icon: XCircle, status: "warning" },
  { label: "Critical Issues", value: "5", icon: AlertTriangle, status: "critical" }
];

const getStatusColor = (status: string) => {
  switch (status) {
    case "online": return "bg-success text-success-foreground";
    case "offline": return "bg-muted text-muted-foreground";
    case "warning": return "bg-warning text-warning-foreground";
    case "critical": return "bg-critical text-critical-foreground";
    default: return "bg-info text-info-foreground";
  }
};

const getStatusIcon = (status: string) => {
  switch (status) {
    case "online": return <CheckCircle className="w-4 h-4 text-success" />;
    case "offline": return <XCircle className="w-4 h-4 text-muted-foreground" />;
    case "warning": return <AlertTriangle className="w-4 h-4 text-warning" />;
    case "critical": return <AlertTriangle className="w-4 h-4 text-critical" />;
    default: return <Monitor className="w-4 h-4 text-info" />;
  }
};

const getTypeIcon = (type: string) => {
  if (type.includes("Windows") || type.includes("macOS") || type.includes("Workstation")) {
    return <Monitor className="w-5 h-5 text-primary" />;
  } else if (type.includes("Server")) {
    return <Server className="w-5 h-5 text-primary" />;
  } else if (type.includes("Mobile")) {
    return <Smartphone className="w-5 h-5 text-primary" />;
  }
  return <Monitor className="w-5 h-5 text-primary" />;
};

export const Endpoints = () => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Endpoints Management</h1>
          <p className="text-muted-foreground">Monitor and manage all connected endpoints</p>
        </div>
        <div className="flex items-center space-x-2">
          <Button variant="outline">
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
          <Button variant="outline">
            <Filter className="w-4 h-4 mr-2" />
            Filter
          </Button>
        </div>
      </div>

      {/* Endpoint Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {endpointStats.map((stat, index) => {
          const Icon = stat.icon;
          return (
            <Card key={index} className="shadow-card">
              <CardContent className="p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">{stat.label}</p>
                    <p className="text-2xl font-bold text-foreground">{stat.value}</p>
                  </div>
                  <Icon className={`w-8 h-8 ${
                    stat.status === 'success' ? 'text-success' :
                    stat.status === 'warning' ? 'text-warning' :
                    stat.status === 'critical' ? 'text-critical' : 'text-primary'
                  }`} />
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
                placeholder="Search endpoints by name, IP address, or user..." 
                className="pl-10"
              />
            </div>
            <Button variant="outline">
              <Filter className="w-4 h-4 mr-2" />
              Advanced Filters
            </Button>
          </div>
        </CardContent>
      </Card>

      <Tabs defaultValue="all" className="w-full">
        <TabsList className="grid w-full grid-cols-5">
          <TabsTrigger value="all">All Endpoints</TabsTrigger>
          <TabsTrigger value="online">Online</TabsTrigger>
          <TabsTrigger value="offline">Offline</TabsTrigger>
          <TabsTrigger value="threats">With Threats</TabsTrigger>
          <TabsTrigger value="outdated">Outdated</TabsTrigger>
        </TabsList>

        <TabsContent value="all" className="space-y-4">
          {endpointData.map((endpoint) => (
            <Card key={endpoint.id} className="shadow-card">
              <CardContent className="p-6">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-4">
                    {getTypeIcon(endpoint.type)}
                    <div>
                      <div className="flex items-center space-x-3">
                        <h3 className="font-semibold text-foreground">{endpoint.name}</h3>
                        {getStatusIcon(endpoint.status)}
                        <Badge className={getStatusColor(endpoint.status)}>
                          {endpoint.status.toUpperCase()}
                        </Badge>
                      </div>
                      <p className="text-sm text-muted-foreground mt-1">
                        {endpoint.type} • {endpoint.user} • {endpoint.ip}
                      </p>
                      <p className="text-sm text-muted-foreground">
                        {endpoint.os} • {endpoint.version}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-6">
                    <div className="text-right">
                      <p className="text-sm font-medium text-foreground">Last Seen</p>
                      <p className="text-sm text-muted-foreground">{endpoint.lastSeen}</p>
                    </div>
                    {endpoint.threats > 0 && (
                      <div className="text-right">
                        <p className="text-sm font-medium text-critical">{endpoint.threats} Threat{endpoint.threats > 1 ? 's' : ''}</p>
                        <p className="text-sm text-muted-foreground">Active</p>
                      </div>
                    )}
                    <div className="flex space-x-2">
                      <Button size="sm" variant="outline">Details</Button>
                      <Button size="sm" variant="outline">Isolate</Button>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </TabsContent>

        <TabsContent value="online">
          <Card className="shadow-card">
            <CardContent className="p-12 text-center">
              <CheckCircle className="w-16 h-16 text-success mx-auto mb-4" />
              <h3 className="text-lg font-medium text-foreground">Online Endpoints</h3>
              <p className="text-muted-foreground">Showing only endpoints that are currently online</p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="offline">
          <Card className="shadow-card">
            <CardContent className="p-12 text-center">
              <XCircle className="w-16 h-16 text-muted-foreground mx-auto mb-4" />
              <h3 className="text-lg font-medium text-foreground">Offline Endpoints</h3>
              <p className="text-muted-foreground">Showing only endpoints that are currently offline</p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="threats">
          <Card className="shadow-card">
            <CardContent className="p-12 text-center">
              <AlertTriangle className="w-16 h-16 text-critical mx-auto mb-4" />
              <h3 className="text-lg font-medium text-foreground">Endpoints with Active Threats</h3>
              <p className="text-muted-foreground">Showing only endpoints with detected threats</p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="outdated">
          <Card className="shadow-card">
            <CardContent className="p-12 text-center">
              <RefreshCw className="w-16 h-16 text-warning mx-auto mb-4" />
              <h3 className="text-lg font-medium text-foreground">Outdated Agents</h3>
              <p className="text-muted-foreground">Showing endpoints with outdated agent versions</p>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};