import React from "react";
import { Box, Typography } from "@mui/material";

export default function MitrePanel({ incident }) {

  const mapping = {
    SSH_BRUTE_FORCE: {
      tactic: "Credential Access",
      technique: "T1110"
    }
  };

  const m = mapping[incident?.type] || {};

  return (
    <Box sx={{
      background: "rgba(255,255,255,0.05)",
      p: 2,
      borderRadius: 2
    }}>
      <Typography>MITRE ATT&CK</Typography>

      <Typography mt={1} color="#a78bfa">
        {m.technique} - {m.tactic}
      </Typography>
    </Box>
  );
}
