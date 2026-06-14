import React from "react";
import { Grid, Card, CardContent, Typography } from "@mui/material";

export default function StatsCards({ incidents }) {

  const stats = {
    total: incidents.length,
    high: incidents.filter(i => i.severity === "HIGH").length,
    medium: incidents.filter(i => i.severity === "MEDIUM").length,
    critical: incidents.filter(i => i.severity === "CRITICAL").length
  };

  return (
    <Grid container spacing={2} mt={2}>
      <Grid item><Card sx={card}><CardContent>
        <Typography>Open Incidents</Typography>
        <Typography variant="h4">{stats.total}</Typography>
      </CardContent></Card></Grid>

      <Grid item><Card sx={{ ...card, background: "#ef4444" }}>
        <CardContent><Typography>Critical</Typography>
        <Typography variant="h4">{stats.critical}</Typography></CardContent>
      </Card></Grid>

      <Grid item><Card sx={{ ...card, background: "#f97316" }}>
        <CardContent><Typography>High</Typography>
        <Typography variant="h4">{stats.high}</Typography></CardContent>
      </Card></Grid>

      <Grid item><Card sx={{ ...card, background: "#22c55e" }}>
        <CardContent><Typography>Medium</Typography>
        <Typography variant="h4">{stats.medium}</Typography></CardContent>
      </Card></Grid>
    </Grid>
  );
}

const card = {
  background: "rgba(255,255,255,0.05)",
  color: "#fff",
  borderRadius: 3
};
