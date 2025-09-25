import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { BarChart3, TrendingUp, Calendar, Download, Filter } from "lucide-react";
import { ResponsiveContainer, LineChart, Line, XAxis, YAxis, Tooltip, Legend, BarChart, Bar, PieChart, Pie, Cell, AreaChart, Area } from "recharts";

const threatTrendData = [
  { date: "Jan 15", malware: 12, network: 8, files: 3, behavior: 5, total: 28 },
  { date: "Jan 16", malware: 15, network: 12, files: 7, behavior: 8, total: 42 },
  { date: "Jan 17", malware: 8, network: 15, files: 4, behavior: 6, total: 33 },
  { date: "Jan 18", malware: 23, network: 18, files: 12, behavior: 15, total: 68 },
  { date: "Jan 19", malware: 18, network: 22, files: 8, behavior: 12, total: 60 },
  { date: "Jan 20", malware: 31, network: 25, files: 18, behavior: 22, total: 96 },
  { date: "Jan 21", malware: 25, network: 30, files: 14, behavior: 18, total: 87 }
];

const endpointData = [
  { name: "Windows", value: 145, color: "hsl(var(--info))" },
  { name: "Linux", value: 67, color: "hsl(var(--success))" },
  { name: "macOS", value: 23, color: "hsl(var(--warning))" },
  { name: "Mobile", value: 12, color: "hsl(var(--critical))" }
];

const severityDistribution = [
  { severity: "Critical", count: 23, percentage: 15 },
  { severity: "High", count: 45, percentage: 29 },
  { severity: "Medium", count: 67, percentage: 43 },
  { severity: "Low", count: 20, percentage: 13 }
];

const topThreats = [
  { name: "PowerShell Execution", count: 34, trend: "+12%" },
  { name: "Registry Modification", count: 28, trend: "+8%" },
  { name: "Suspicious Network", count: 22, trend: "-3%" },
  { name: "File System Changes", count: 18, trend: "+15%" },
  { name: "Process Injection", count: 14, trend: "+5%" }
];

const performanceMetrics = [
  { metric: "Detection Rate", value: "99.7%", change: "+0.2%" },
  { metric: "False Positives", value: "0.3%", change: "-0.1%" },
  { metric: "Response Time", value: "1.2s", change: "-0.3s" },
  { metric: "Coverage", value: "247/247", change: "0" }
];

export const Analytics = () => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Security Analytics</h1>
          <p className="text-muted-foreground">Comprehensive security insights and threat intelligence</p>
        </div>
        <div className="flex items-center space-x-2">
          <Button variant="outline">
            <Filter className="w-4 h-4 mr-2" />
            Filter
          </Button>
          <Button variant="outline">
            <Calendar className="w-4 h-4 mr-2" />
            Date Range
          </Button>
          <Button variant="outline">
            <Download className="w-4 h-4 mr-2" />
            Export Report
          </Button>
        </div>
      </div>

      {/* Performance Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {performanceMetrics.map((metric, index) => (
          <Card key={index} className="shadow-card">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">{metric.metric}</p>
                  <p className="text-2xl font-bold text-foreground">{metric.value}</p>
                </div>
                <div className="flex items-center space-x-1">
                  <TrendingUp className="w-4 h-4 text-success" />
                  <span className={`text-sm font-medium ${metric.change.startsWith('+') || metric.change.startsWith('-') ? 
                    metric.change.startsWith('+') ? 'text-success' : 'text-critical' : 'text-muted-foreground'}`}>
                    {metric.change}
                  </span>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <Tabs defaultValue="trends" className="w-full">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="trends">Threat Trends</TabsTrigger>
          <TabsTrigger value="distribution">Distribution</TabsTrigger>
          <TabsTrigger value="endpoints">Endpoints</TabsTrigger>
          <TabsTrigger value="performance">Performance</TabsTrigger>
        </TabsList>

        <TabsContent value="trends" className="space-y-6">
          <Card className="shadow-card">
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <BarChart3 className="w-5 h-5 text-primary" />
                <span>7-Day Threat Trend Analysis</span>
              </CardTitle>
              <CardDescription>Historical threat detection patterns and trends</CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={400}>
                <AreaChart data={threatTrendData}>
                  <XAxis dataKey="date" stroke="hsl(var(--muted-foreground))" />
                  <YAxis stroke="hsl(var(--muted-foreground))" />
                  <Tooltip 
                    contentStyle={{
                      backgroundColor: "hsl(var(--card))",
                      border: "1px solid hsl(var(--border))",
                      borderRadius: "8px"
                    }}
                  />
                  <Legend />
                  <Area type="monotone" dataKey="malware" stackId="1" stroke="hsl(var(--critical))" fill="hsl(var(--critical))" fillOpacity={0.7} name="Malware" />
                  <Area type="monotone" dataKey="network" stackId="1" stroke="hsl(var(--warning))" fill="hsl(var(--warning))" fillOpacity={0.7} name="Network" />
                  <Area type="monotone" dataKey="files" stackId="1" stroke="hsl(var(--info))" fill="hsl(var(--info))" fillOpacity={0.7} name="Files" />
                  <Area type="monotone" dataKey="behavior" stackId="1" stroke="hsl(var(--success))" fill="hsl(var(--success))" fillOpacity={0.7} name="Behavior" />
                </AreaChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>

          <Card className="shadow-card">
            <CardHeader>
              <CardTitle>Top Threat Categories</CardTitle>
              <CardDescription>Most frequent threat types detected this week</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {topThreats.map((threat, index) => (
                  <div key={index} className="flex items-center justify-between p-3 border border-border rounded-lg">
                    <div className="flex items-center space-x-3">
                      <div className="w-8 h-8 bg-primary/10 rounded-full flex items-center justify-center">
                        <span className="text-sm font-bold text-primary">{index + 1}</span>
                      </div>
                      <span className="font-medium text-foreground">{threat.name}</span>
                    </div>
                    <div className="flex items-center space-x-4">
                      <span className="text-2xl font-bold text-foreground">{threat.count}</span>
                      <Badge variant={threat.trend.startsWith('+') ? 'destructive' : 'default'}>
                        {threat.trend}
                      </Badge>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="distribution" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card className="shadow-card">
              <CardHeader>
                <CardTitle>Severity Distribution</CardTitle>
                <CardDescription>Breakdown of threats by severity level</CardDescription>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={severityDistribution}>
                    <XAxis dataKey="severity" stroke="hsl(var(--muted-foreground))" />
                    <YAxis stroke="hsl(var(--muted-foreground))" />
                    <Tooltip 
                      contentStyle={{
                        backgroundColor: "hsl(var(--card))",
                        border: "1px solid hsl(var(--border))",
                        borderRadius: "8px"
                      }}
                    />
                    <Bar dataKey="count" fill="hsl(var(--primary))" />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            <Card className="shadow-card">
              <CardHeader>
                <CardTitle>Endpoint Distribution</CardTitle>
                <CardDescription>Threats by operating system</CardDescription>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={endpointData}
                      cx="50%"
                      cy="50%"
                      outerRadius={80}
                      fill="#8884d8"
                      dataKey="value"
                      label={({ name, value, percent }) => `${name}: ${value} (${(percent * 100).toFixed(0)}%)`}
                    >
                      {endpointData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="endpoints">
          <Card className="shadow-card">
            <CardHeader>
              <CardTitle>Endpoint Analysis</CardTitle>
              <CardDescription>Detailed endpoint security metrics and coverage</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-center py-12">
                <BarChart3 className="w-16 h-16 text-muted-foreground mx-auto mb-4" />
                <p className="text-lg font-medium text-foreground">Endpoint Analytics</p>
                <p className="text-muted-foreground">Detailed endpoint metrics coming soon</p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="performance">
          <Card className="shadow-card">
            <CardHeader>
              <CardTitle>System Performance</CardTitle>
              <CardDescription>EDR system performance and health metrics</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-center py-12">
                <TrendingUp className="w-16 h-16 text-muted-foreground mx-auto mb-4" />
                <p className="text-lg font-medium text-foreground">Performance Metrics</p>
                <p className="text-muted-foreground">Detailed performance analytics coming soon</p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};