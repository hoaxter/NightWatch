import { Activity, Shield, Users, AlertCircle } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";

interface StatItemProps {
  label: string;
  value: string | number;
  change: string;
  positive?: boolean;
  icon: React.ElementType;
}

const StatItem = ({ label, value, change, positive = true, icon: Icon }: StatItemProps) => (
  <Card className="shadow-card">
    <CardContent className="p-6">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-muted-foreground">{label}</p>
          <p className="text-3xl font-bold text-card-foreground">{value}</p>
          <p className={`text-sm ${positive ? 'text-success' : 'text-critical'}`}>
            {change}
          </p>
        </div>
        <div className="p-3 bg-primary/10 rounded-lg">
          <Icon className="w-8 h-8 text-primary" />
        </div>
      </div>
    </CardContent>
  </Card>
);

export const StatsOverview = () => {
  const stats = [
    {
      label: "Active Endpoints",
      value: 847,
      change: "+12 from yesterday",
      positive: true,
      icon: Users,
    },
    {
      label: "Threats Blocked",
      value: 1247,
      change: "+23% this week", 
      positive: true,
      icon: Shield,
    },
    {
      label: "System Health", 
      value: "98.7%",
      change: "+0.3% uptime",
      positive: true,
      icon: Activity,
    },
    {
      label: "Active Alerts",
      value: 17,
      change: "-5 from yesterday",
      positive: true,
      icon: AlertCircle,
    },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
      {stats.map((stat, index) => (
        <StatItem key={index} {...stat} />
      ))}
    </div>
  );
};