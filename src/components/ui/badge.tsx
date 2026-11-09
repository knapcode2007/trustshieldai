import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "../../lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-md border px-2.5 py-0.5 text-xs font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
  {
    variants: {
      variant: {
        default:
          "border-transparent bg-blue-600/20 text-blue-300 border-blue-500/30",
        secondary:
          "border-transparent bg-slate-800 text-slate-300 border-slate-700",
        destructive:
          "border-transparent bg-red-950/60 text-red-400 border-red-500/30",
        outline: "text-slate-300 border-slate-700",
        clean:
          "border-emerald-500/30 bg-emerald-950/50 text-emerald-400",
        suspicious:
          "border-amber-500/30 bg-amber-950/50 text-amber-400",
        phishing:
          "border-orange-500/30 bg-orange-950/60 text-orange-400",
        malicious:
          "border-red-500/40 bg-red-950/70 text-red-300 animate-pulse",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  );
}

export { Badge, badgeVariants };
