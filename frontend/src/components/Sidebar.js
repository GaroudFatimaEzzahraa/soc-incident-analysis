import React from "react";
import { Box } from "@mui/material";
import { useNavigate } from "react-router-dom";

import DashboardIcon from "@mui/icons-material/Dashboard";
import ListAltIcon from "@mui/icons-material/ListAlt";

export default function Sidebar() {

  const navigate = useNavigate();

  return (
    <Box sx={{
      width: 80,
      height: "100vh",
      background: "#0f0c29",
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      pt: 3,
      gap: 4
    }}>

      {/* DASHBOARD */}
      <Box
        onClick={() => navigate("/")}
        sx={{
          cursor: "pointer",
          color: "#a78bfa",
          "&:hover": { color: "#22c55e", tranform:"scale(1.2)" }
        }}
      >
        <DashboardIcon />
      </Box>

      {/* INCIDENTS */}
      <Box
        onClick={() => navigate("/incidents")}
        sx={{
          cursor: "pointer",
          color: "#c4b5fd",
          "&:hover": { color: "#22c55e" }
        }}
      >
        <ListAltIcon />
      </Box>

    </Box>
  );
}
