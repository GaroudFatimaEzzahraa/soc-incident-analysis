import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Box, Typography, Card, CardContent, Table, TableHead,
  TableRow, TableCell, TableBody, Chip, LinearProgress,
  Stack, TextField, Select, MenuItem, InputAdornment,
  IconButton, Tooltip,
} from "@mui/material";
import SearchIcon from "@mui/icons-material/Search";
import FilterListIcon from "@mui/icons-material/FilterList";
import RefreshIcon from "@mui/icons-material/Refresh";
import SecurityIcon from "@mui/icons-material/Security";
import BugReportIcon from "@mui/icons-material/BugReport";
import WarningAmberIcon from "@mui/icons-material/WarningAmber";

const WS_URL = "ws://192.168.137.130:8000/ws/incidents";

const glass = {
  background: "rgba(255,255,255,0.05)",
  borderRadius: 3,
  backdropFilter: "blur(10px)",
};

const cardBorder = function (color) {
  return {
    ...glass,
    border: "1px solid " + color,
    boxShadow: "0 0 12px " + color + "44",
  };
};

const head = {
  color: "#a5b4fc",
  fontWeight: 700,
  fontSize: "0.75rem",
  letterSpacing: "0.08em",
  textTransform: "uppercase",
};

const cell = { color: "#fff" };

const SEVERITY_COLOR = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  MEDIUM: "#fbc02d",
  LOW: "#22c55e",
};

const STATUS_COLOR = {
  OPEN: "#ef4444",
  INVESTIGATING: "#fbc02d",
  CLOSED: "#22c55e",
};

const ATTACK_ICONS = {
  SSH_BRUTE_FORCE: BugReportIcon,
  FULL_KILL_CHAIN: SecurityIcon,
  NETWORK_RECONNAISSANCE: SecurityIcon,
  DATA_EXFILTRATION_ATTEMPT: BugReportIcon,
};

function priorityColor(score) {
  if (score >= 80) return "#ef4444";
  if (score >= 60) return "#f97316";
  if (score >= 40) return "#fbc02d";
  return "#22c55e";
}

function PriorityBar(props) {
  var score = props.score || 0;
  var color = priorityColor(score);

  return (
    <Stack direction="row" alignItems="center" spacing={1}>
      <Typography
        variant="body2"
        fontWeight={700}
        sx={{ color: color, minWidth: 28, fontSize: "0.8rem" }}
      >
        {score}
      </Typography>
      <LinearProgress
        variant="determinate"
        value={score}
        sx={{
          width: 56,
          height: 6,
          borderRadius: 3,
          backgroundColor: "rgba(255,255,255,0.08)",
          "& .MuiLinearProgress-bar": { backgroundColor: color, borderRadius: 3 },
        }}
      />
    </Stack>
  );
}

function StatBadge(props) {
  return (
    <Card sx={cardBorder(props.color)}>
      <CardContent sx={{ py: 1.5, px: 2, "&:last-child": { pb: 1.5 } }}>
        <Typography
          variant="caption"
          sx={{ color: "#9ca3af", textTransform: "uppercase", letterSpacing: "0.08em" }}
        >
          {props.label}
        </Typography>
        <Typography variant="h4" fontWeight={800} sx={{ color: props.color }}>
          {props.value}
        </Typography>
      </CardContent>
    </Card>
  );
}

function StatusDot(props) {
  var color = props.connected ? "#22c55e" : "#ef4444";

  return (
    <Box
      component="span"
      sx={{
        width: 8,
        height: 8,
        borderRadius: "50%",
        backgroundColor: color,
        boxShadow: "0 0 6px " + color,
        display: "inline-block",
        mr: 1,
      }}
    />
  );
}

function EmptyState() {
  return (
    <TableRow>
      <TableCell colSpan={11} sx={{ textAlign: "center", py: 6, borderBottom: "none" }}>
        <WarningAmberIcon sx={{ fontSize: 40, color: "#4b5563", mb: 1, display: "block", mx: "auto" }} />
        <Typography color="#6b7280" variant="body2">
          No incidents match the current filters.
        </Typography>
      </TableCell>
    </TableRow>
  );
}

var inputSx = {
  "& .MuiOutlinedInput-root": {
    color: "#fff",
    backgroundColor: "rgba(255,255,255,0.05)",
    borderRadius: 2,
    "& fieldset": { borderColor: "rgba(255,255,255,0.12)" },
    "&:hover fieldset": { borderColor: "rgba(165,180,252,0.4)" },
    "&.Mui-focused fieldset": { borderColor: "#a78bfa" },
  },
  "& .MuiInputBase-input::placeholder": { color: "#6b7280" },
  "& .MuiSelect-icon": { color: "#9ca3af" },
};

var SEVERITIES = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"];
var STATUSES = ["ALL", "OPEN", "INVESTIGATING", "CLOSED"];

export default function Incidents() {
  var navigate = useNavigate();

  var incidentsState = useState([]);
  var incidents = incidentsState[0];
  var setIncidents = incidentsState[1];

  var connectedState = useState(false);
  var connected = connectedState[0];
  var setConnected = connectedState[1];

  var searchState = useState("");
  var search = searchState[0];
  var setSearch = searchState[1];

  var severityState = useState("ALL");
  var filterSeverity = severityState[0];
  var setFilterSeverity = severityState[1];

  var typeState = useState("ALL");
  var filterType = typeState[0];
  var setFilterType = typeState[1];

  var statusState = useState("ALL");
  var filterStatus = statusState[0];
  var setFilterStatus = statusState[1];

  var updatedState = useState(null);
  var lastUpdated = updatedState[0];
  var setLastUpdated = updatedState[1];

  useEffect(function () {
    var ws = new WebSocket(WS_URL);

    ws.onopen = function () {
      setConnected(true);
    };

    ws.onclose = function () {
      setConnected(false);
    };

    ws.onmessage = function (event) {
      var data = JSON.parse(event.data);
      var seen = new Set();

      var unique = data.filter(function (i) {
        if (seen.has(i.id)) return false;
        seen.add(i.id);
        return true;
      });

      setIncidents(unique);
      setLastUpdated(new Date().toLocaleTimeString());
    };

    return function () {
      ws.close();
    };
  }, []);

  var attackTypes = ["ALL"].concat(
    Array.from(new Set(incidents.map(function (i) { return i.type; }).filter(Boolean)))
  );

  var filtered = incidents
    .filter(function (i) {
      var q = search.toLowerCase();
      var status = i.status || "OPEN";

      var matchSearch =
        !search ||
        (i.ip || "").toLowerCase().includes(q) ||
        (i.type || "").toLowerCase().includes(q) ||
        (i.id || "").toLowerCase().includes(q) ||
        (i.target_agent || "").toLowerCase().includes(q) ||
        (i.duration || "").toLowerCase().includes(q) ||
        ((i.mitre && i.mitre.technique) || "").toLowerCase().includes(q);

      var matchSev = filterSeverity === "ALL" || i.severity === filterSeverity;
      var matchType = filterType === "ALL" || i.type === filterType;
      var matchStatus = filterStatus === "ALL" || status === filterStatus;

      return matchSearch && matchSev && matchType && matchStatus;
    })
    .sort(function (a, b) {
      return (b.priority || 0) - (a.priority || 0);
    });

  var stats = {
    total: incidents.length,
    critical: incidents.filter(function (i) { return i.severity === "CRITICAL"; }).length,
    high: incidents.filter(function (i) { return i.severity === "HIGH"; }).length,
    medium: incidents.filter(function (i) { return i.severity === "MEDIUM"; }).length,
    low: incidents.filter(function (i) { return i.severity === "LOW"; }).length,
    open: incidents.filter(function (i) { return (i.status || "OPEN") === "OPEN"; }).length,
  };

  return (
    <Box
      sx={{
        minHeight: "100vh",
        p: 4,
        color: "#fff",
        background: "linear-gradient(135deg, #0f0c29, #302b63, #24243e)",
      }}
    >
      <Stack direction="row" justifyContent="space-between" alignItems="flex-start" mb={3}>
        <Box>
          <Typography variant="h4" fontWeight={700}>
            Incidents
          </Typography>
          <Typography variant="body2" sx={{ color: "#9ca3af", mt: 0.5 }}>
            <StatusDot connected={connected} />
            {connected ? "Live stream active" : "Disconnected"}
            {lastUpdated && (
              <Typography component="span" variant="caption" sx={{ color: "#6b7280", ml: 1 }}>
                {" Last update " + lastUpdated}
              </Typography>
            )}
          </Typography>
        </Box>

        <Tooltip title="Auto-refreshed via WebSocket">
          <IconButton sx={{ color: "#a78bfa" }}>
            <RefreshIcon />
          </IconButton>
        </Tooltip>
      </Stack>

      <Box
        sx={{
          display: "grid",
          gridTemplateColumns: "repeat(6, 1fr)",
          gap: 2,
          mb: 3,
        }}
      >
        <StatBadge label="Total" value={stats.total} color="#6366f1" />
        <StatBadge label="Open" value={stats.open} color="#ef4444" />
        <StatBadge label="Critical" value={stats.critical} color="#ef4444" />
        <StatBadge label="High" value={stats.high} color="#f97316" />
        <StatBadge label="Medium" value={stats.medium} color="#fbc02d" />
        <StatBadge label="Low" value={stats.low} color="#22c55e" />
      </Box>

      <Card sx={{ ...glass, mb: 3, border: "1px solid rgba(255,255,255,0.07)" }}>
        <CardContent sx={{ py: 1.5, "&:last-child": { pb: 1.5 } }}>
          <Stack direction="row" spacing={2} alignItems="center">
            <FilterListIcon sx={{ color: "#6b7280", fontSize: 20 }} />

            <TextField
              placeholder="Search by IP, type, ID, host, duration, MITRE..."
              size="small"
              value={search}
              onChange={function (e) { setSearch(e.target.value); }}
              sx={{ ...inputSx, minWidth: 310 }}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchIcon sx={{ color: "#6b7280", fontSize: 18 }} />
                  </InputAdornment>
                ),
              }}
            />

            <Select
              value={filterSeverity}
              onChange={function (e) { setFilterSeverity(e.target.value); }}
              size="small"
              sx={{ ...inputSx, minWidth: 150, color: "#fff" }}
            >
              {SEVERITIES.map(function (s) {
                return (
                  <MenuItem key={s} value={s}>
                    {s === "ALL" ? "All severities" : s}
                  </MenuItem>
                );
              })}
            </Select>

            <Select
              value={filterType}
              onChange={function (e) { setFilterType(e.target.value); }}
              size="small"
              sx={{ ...inputSx, minWidth: 190, color: "#fff" }}
            >
              {attackTypes.map(function (t) {
                return (
                  <MenuItem key={t} value={t}>
                    {t === "ALL" ? "All attack types" : t}
                  </MenuItem>
                );
              })}
            </Select>

            <Select
              value={filterStatus}
              onChange={function (e) { setFilterStatus(e.target.value); }}
              size="small"
              sx={{ ...inputSx, minWidth: 170, color: "#fff" }}
            >
              {STATUSES.map(function (s) {
                return (
                  <MenuItem key={s} value={s}>
                    {s === "ALL" ? "All statuses" : s}
                  </MenuItem>
                );
              })}
            </Select>

            <Typography variant="caption" sx={{ color: "#6b7280", ml: "auto !important" }}>
              {filtered.length + " of " + incidents.length + " incidents"}
            </Typography>
          </Stack>
        </CardContent>
      </Card>

      <Card sx={{ ...glass, border: "1px solid rgba(255,255,255,0.07)" }}>
        <CardContent sx={{ p: 0, "&:last-child": { pb: 0 } }}>
          <Box
            sx={{
              px: 2.5,
              py: 2,
              borderBottom: "1px solid rgba(255,255,255,0.06)",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <Typography fontWeight={600} fontSize="0.95rem">
              Live Incident Feed
            </Typography>
            <Typography variant="caption" sx={{ color: "#a78bfa" }}>
              Sorted by priority score
            </Typography>
          </Box>

          <Table>
            <TableHead>
              <TableRow>
                <TableCell sx={head}>ID</TableCell>
                <TableCell sx={head}>Attack type</TableCell>
                <TableCell sx={head}>Attacker IP</TableCell>
                <TableCell sx={head}>Target</TableCell>
                <TableCell sx={head}>MITRE</TableCell>
                <TableCell sx={head}>Duration</TableCell>
                <TableCell sx={head}>Status</TableCell>
                <TableCell sx={head}>Severity</TableCell>
                <TableCell sx={head}>Priority</TableCell>
                <TableCell sx={head}>Confidence</TableCell>
                <TableCell sx={head}>Alerts</TableCell>
              </TableRow>
            </TableHead>

            <TableBody>
              {filtered.length === 0 ? (
                <EmptyState />
              ) : (
                filtered.map(function (inc) {
                  var IconComp = ATTACK_ICONS[inc.type] || null;
                  var sevColor = SEVERITY_COLOR[inc.severity] || "#555";
                  var status = inc.status || "OPEN";
                  var statusColor = STATUS_COLOR[status] || "#9ca3af";
                  var mitreTechnique = inc.mitre && inc.mitre.technique ? inc.mitre.technique : "-";

                  var confColor =
                    inc.confidence >= 80
                      ? "#22c55e"
                      : inc.confidence >= 60
                      ? "#fbc02d"
                      : "#9ca3af";

                  return (
                    <TableRow
                      key={inc.id}
                      onClick={function () { navigate("/incident/" + inc.id); }}
                      sx={{
                        cursor: "pointer",
                        "& .MuiTableCell-root": {
                          borderBottom: "1px solid rgba(255,255,255,0.04)",
                          py: 1.4,
                        },
                        "&:hover": { background: "rgba(167,139,250,0.07)" },
                      }}
                    >
                      <TableCell sx={{ ...cell, fontFamily: "monospace", fontSize: "0.78rem", color: "#a5b4fc" }}>
                        {inc.id}
                      </TableCell>

                      <TableCell sx={cell}>
                        <Stack direction="row" alignItems="center" spacing={0.5}>
                          {IconComp && <IconComp sx={{ fontSize: 15, color: "#a5b4fc" }} />}
                          <Typography variant="body2" fontWeight={500}>
                            {inc.type || "-"}
                          </Typography>
                        </Stack>
                      </TableCell>

                      <TableCell sx={{ ...cell, fontFamily: "monospace", fontSize: "0.82rem", color: "#38bdf8" }}>
                        {inc.ip || "-"}
                      </TableCell>

                      <TableCell sx={{ ...cell, fontFamily: "monospace", fontSize: "0.78rem", color: "#9ca3af" }}>
                        {inc.target_agent || "-"}
                      </TableCell>

                      <TableCell sx={{ ...cell, fontFamily: "monospace", color: "#a78bfa" }}>
                        {mitreTechnique}
                      </TableCell>

                      <TableCell sx={{ ...cell, color: "#e5e7eb" }}>
                        {inc.duration || "N/A"}
                      </TableCell>

                      <TableCell>
                        <Chip
                          label={status}
                          size="small"
                          sx={{
                            backgroundColor: statusColor + "22",
                            color: statusColor,
                            border: "1px solid " + statusColor + "66",
                            fontWeight: 700,
                            fontSize: "0.68rem",
                          }}
                        />
                      </TableCell>

                      <TableCell>
                        <Chip
                          label={inc.severity || "-"}
                          size="small"
                          sx={{
                            backgroundColor: sevColor + "22",
                            color: sevColor,
                            border: "1px solid " + sevColor + "66",
                            fontWeight: 700,
                            fontSize: "0.68rem",
                          }}
                        />
                      </TableCell>

                      <TableCell>
                        <PriorityBar score={inc.priority} />
                      </TableCell>

                      <TableCell sx={{ ...cell, fontSize: "0.82rem" }}>
                        {inc.confidence ? (
                          <Typography variant="body2" sx={{ color: confColor }}>
                            {inc.confidence + "%"}
                          </Typography>
                        ) : (
                          <Typography variant="body2" sx={{ color: "#4b5563" }}>
                            N/A
                          </Typography>
                        )}
                      </TableCell>

                      <TableCell sx={{ ...cell, fontSize: "0.82rem" }}>
                        <Chip
                          label={inc.alert_count || "-"}
                          size="small"
                          sx={{
                            backgroundColor: "rgba(99,102,241,0.15)",
                            color: "#a5b4fc",
                            fontWeight: 600,
                            fontSize: "0.7rem",
                            height: 20,
                          }}
                        />
                      </TableCell>
                    </TableRow>
                  );
                })
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Typography variant="caption" sx={{ color: "#4b5563", display: "block", mt: 2, textAlign: "center" }}>
        Click any row to view full details, MITRE mapping, AI explanation, SOC actions, and attack timeline.
      </Typography>
    </Box>
  );
}
