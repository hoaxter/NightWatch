import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ResponsiveContainer, LineChart, Line, XAxis, YAxis, Tooltip, Legend, AreaChart, Area } from "recharts";

const threatData = [
  { time: "00:00", malware: 4, network: 8, files: 2, behavior: 5 },
  { time: "04:00", malware: 12, network: 15, files: 5, behavior: 8 },
  { time: "08:00", malware: 23, network: 28, files: 12, behavior: 15 },
  { time: "12:00", malware: 18, network: 22, files: 8, behavior: 12 },
  { time: "16:00", malware: 31, network: 35, files: 18, behavior: 22 },
  { time: "20:00", malware: 25, network: 30, files: 14, behavior: 18 },
];

const severityData = [
  { name: "Critical", value: 12, color: "hsl(var(--critical))" },
  { name: "High", value: 28, color: "hsl(var(--warning))" },
  { name: "Medium", value: 45, color: "hsl(var(--info))" },
  { name: "Low", value: 63, color: "hsl(var(--success))" },
];

export const ThreatChart = () => {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <Card className="shadow-card">
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <div className="w-2 h-2 bg-primary rounded-full"></div>
            <span>Threat Detection Timeline</span>
          </CardTitle>
          <CardDescription>Real-time threat detection over the last 24 hours</CardDescription>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={threatData}>
              <XAxis dataKey="time" stroke="hsl(var(--muted-foreground))" />
              <YAxis stroke="hsl(var(--muted-foreground))" />
              <Tooltip 
                contentStyle={{
                  backgroundColor: "hsl(var(--card))",
                  border: "1px solid hsl(var(--border))",
                  borderRadius: "8px"
                }}
              />
              <Legend />
              <Line 
                type="monotone" 
                dataKey="malware" 
                stroke="hsl(var(--critical))" 
                strokeWidth={2}
                name="Malware"
              />
              <Line 
                type="monotone" 
                dataKey="network" 
                stroke="hsl(var(--warning))" 
                strokeWidth={2}
                name="Network"
              />
              <Line 
                type="monotone" 
                dataKey="files" 
                stroke="hsl(var(--info))" 
                strokeWidth={2}
                name="Files"
              />
              <Line 
                type="monotone" 
                dataKey="behavior" 
                stroke="hsl(var(--success))" 
                strokeWidth={2}
                name="Behavior"
              />
            </LineChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      <Card className="shadow-card">
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <div className="w-2 h-2 bg-primary rounded-full"></div>
            <span>Severity Distribution</span>
          </CardTitle>
          <CardDescription>Threat severity levels in the last 7 days</CardDescription>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={300}>
            <AreaChart data={severityData}>
              <XAxis dataKey="name" stroke="hsl(var(--muted-foreground))" />
              <YAxis stroke="hsl(var(--muted-foreground))" />
              <Tooltip
                contentStyle={{
                  backgroundColor: "hsl(var(--card))",
                  border: "1px solid hsl(var(--border))",
                  borderRadius: "8px"
                }}
              />
              <Area 
                type="monotone" 
                dataKey="value" 
                fill="url(#gradient)"
                stroke="hsl(var(--primary))"
                strokeWidth={2}
              />
              <defs>
                <linearGradient id="gradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="hsl(var(--primary))" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="hsl(var(--primary))" stopOpacity={0.1} />
                </linearGradient>
              </defs>
            </AreaChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>
    </div>
  );
};