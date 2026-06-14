import React from "react";
import { Box, Typography } from "@mui/material";

export default function Topbar() {
  return (
    <Box
      sx={{
        height: 60,
        background: "#0f172a",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        px: 3,
        borderBottom: "1px solid #1e293b"
      }}
    >
      <Typography sx={{ color: "#e2e8f0" }}>
        SOC Incident Correlation Platform
      </Typography>

      <Typography sx={{ color: "#94a3b8" }}>
        Real-Time Monitoring
      </Typography>
    </Box>
  );
}
