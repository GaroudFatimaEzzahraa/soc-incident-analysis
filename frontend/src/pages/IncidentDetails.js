import React, { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  Box, Typography, Card, CardContent, Chip,
  LinearProgress, Stack, Divider, IconButton,
  List, ListItem, ListItemText, Button,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";

const WS_URL = "ws://192.168.137.130:8000/ws/incidents";
const API_URL = "http://192.168.137.130:8000";

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

const glass = {
  background: "rgba(255,255,255,0.05)",
  borderRadius: 3,
  backdropFilter: "blur(10px)",
};

function priorityColor(score) {
  if (score >= 80) return "#ef4444";
  if (score >= 60) return "#f97316";
  if (score >= 40) return "#fbc02d";
  return "#22c55e";
}

function mlColor(score) {
  if (score >= 70) return "#ef4444";
  if (score >= 40) return "#fbc02d";
  return "#22c55e";
}

function SectionTitle(props) {
  return (
    <Typography
      variant="overline"
      sx={{ color: "#a78bfa", letterSpacing: "0.12em", fontWeight: 700 }}
    >
      {props.children}
    </Typography>
  );
}

function InfoRow(props) {
  const value = props.value;
  const display =
    value !== null && value !== undefined && value !== "" && value !== "N/A"
      ? value
      : "N/A";

  return (
    <Box
      sx={{
        display: "grid",
        gridTemplateColumns: {
          xs: "130px 1fr",
          md: "180px 1fr",
        },
        alignItems: "center",
        py: 0.7,
      }}
    >
      <Typography variant="body2" sx={{ color: "#94a3b8", fontWeight: 500 }}>
        {props.label}
      </Typography>

      <Typography
        variant="body2"
        fontWeight={700}
        sx={{
          fontFamily: props.mono ? "monospace" : "inherit",
          color: display === "N/A" ? "#64748b" : "#ffffff",
          wordBreak: "break-word",
        }}
      >
        {display}
      </Typography>
    </Box>
  );
}

function PriorityGauge(props) {
  const score = props.score || 0;
  const color = priorityColor(score);

  return (
    <Box>
      <Stack direction="row" justifyContent="space-between" mb={0.5}>
        <Typography variant="caption" sx={{ color: "#cbd5e1" }}>
          Priority Score
        </Typography>
        <Typography variant="caption" fontWeight={700} sx={{ color: color }}>
          {score} / 100
        </Typography>
      </Stack>

      <LinearProgress
        variant="determinate"
        value={score}
        sx={{
          height: 10,
          borderRadius: 5,
          backgroundColor: "rgba(255,255,255,0.08)",
          "& .MuiLinearProgress-bar": {
            backgroundColor: color,
            borderRadius: 5,
          },
        }}
      />
    </Box>
  );
}

function MachineLearningSection(props) {
  const ml = props.ml;
  const score = ml ? ml.anomaly_score || 0 : 0;
  const color = mlColor(score);

  return (
    <Card sx={glass}>
      <CardContent>
        <SectionTitle>Machine Learning Analysis</SectionTitle>
        <Divider sx={{ my: 1, borderColor: "rgba(255,255,255,0.06)" }} />

        <InfoRow label="Model" value={ml ? ml.model : "N/A"} />
        <InfoRow label="Prediction" value={ml ? ml.prediction : "N/A"} />
        <InfoRow label="Anomaly Score" value={ml ? score + " / 100" : "N/A"} />

        <Box mt={1.5}>
          <Stack direction="row" justifyContent="space-between" mb={0.5}>
            <Typography variant="caption" sx={{ color: "#cbd5e1" }}>
              Behavioral anomaly score
            </Typography>
            <Typography variant="caption" fontWeight={700} sx={{ color: color }}>
              {score}%
            </Typography>
          </Stack>

          <LinearProgress
            variant="determinate"
            value={score}
            sx={{
              height: 10,
              borderRadius: 5,
              backgroundColor: "rgba(255,255,255,0.08)",
              "& .MuiLinearProgress-bar": {
                backgroundColor: color,
                borderRadius: 5,
              },
            }}
          />
        </Box>

        {ml && ml.features && (
          <Box sx={{ mt: 2 }}>
            <SectionTitle>ML Features</SectionTitle>
            <InfoRow label="Alert Count" value={ml.features.alert_count} />
            <InfoRow label="Priority" value={ml.features.priority} />
            <InfoRow label="Confidence" value={ml.features.confidence} />
            <InfoRow label="Severity Score" value={ml.features.severity_score} />
            <InfoRow label="Attack Type Score" value={ml.features.attack_type_score} />
          </Box>
        )}
      </CardContent>
    </Card>
  );
}

function ExplainabilitySection(props) {
  const explanation = props.explanation;
  if (!explanation || explanation.length === 0) return null;

  return (
    <Box>
      <SectionTitle>AI Explanation (XAI)</SectionTitle>

      <Card
        variant="outlined"
        sx={{
          mt: 1,
          backgroundColor: "rgba(167,139,250,0.05)",
          borderColor: "rgba(167,139,250,0.25)",
          borderRadius: 2,
        }}
      >
        <CardContent sx={{ py: 1, "&:last-child": { pb: 1 } }}>
          <List dense disablePadding>
            {explanation.map(function (reason, idx) {
              return (
                <ListItem key={idx} disableGutters sx={{ py: 0.4, alignItems: "flex-start" }}>
                  <Typography variant="body2" sx={{ color: "#22c55e", mr: 1, mt: 0.1 }}>
                    V
                  </Typography>
                  <ListItemText
                    primary={reason}
                    primaryTypographyProps={{ variant: "body2", sx: { color: "#cbd5e1" } }}
                  />
                </ListItem>
              );
            })}
          </List>
        </CardContent>
      </Card>
    </Box>
  );
}

function RecommendedActionsSection(props) {
  const actions = props.actions;
  if (!actions || actions.length === 0) return null;

  return (
    <Box>
      <SectionTitle>Recommended SOC Actions</SectionTitle>

      <Card
        variant="outlined"
        sx={{
          mt: 1,
          backgroundColor: "rgba(34,197,94,0.05)",
          borderColor: "rgba(34,197,94,0.25)",
          borderRadius: 2,
        }}
      >
        <CardContent sx={{ py: 1, "&:last-child": { pb: 1 } }}>
          <List dense disablePadding>
            {actions.map(function (action, idx) {
              return (
                <ListItem key={idx} disableGutters sx={{ py: 0.4, alignItems: "flex-start" }}>
                  <Typography variant="body2" sx={{ color: "#38bdf8", mr: 1, mt: 0.1 }}>
                    {idx + 1}.
                  </Typography>
                  <ListItemText
                    primary={action}
                    primaryTypographyProps={{ variant: "body2", sx: { color: "#cbd5e1" } }}
                  />
                </ListItem>
              );
            })}
          </List>
        </CardContent>
      </Card>
    </Box>
  );
}

function TimelineSection(props) {
  const timeline = props.timeline;
  if (!timeline || timeline.length === 0) return null;

  return (
    <Box>
      <SectionTitle>Attack Timeline</SectionTitle>

      <Stack spacing={1} mt={1}>
        {timeline.map(function (step, idx) {
          return (
            <Stack
              key={idx}
              direction="row"
              spacing={1.5}
              alignItems="flex-start"
              sx={{
                borderLeft: "2px solid rgba(167,139,250,0.3)",
                pl: 1.5,
                py: 0.3,
              }}
            >
              <Box>
                <Typography variant="caption" sx={{ color: "#94a3b8" }} display="block">
                  {step.time}
                </Typography>

                <Typography variant="body2" fontWeight={500} sx={{ color: "#ffffff" }}>
                  {step.event}
                  {step.src_ip && (
                    <Typography component="span" variant="caption" sx={{ color: "#cbd5e1" }} ml={1}>
                      ({step.src_ip})
                    </Typography>
                  )}
                </Typography>
              </Box>
            </Stack>
          );
        })}
      </Stack>
    </Box>
  );
}

function resolveTargetHost(incident) {
  if (!incident) return "N/A";

  const candidates = [
    incident.target_agent,
    incident.target_host,
    incident.agent_name,
    incident.hostname,
  ];

  for (let i = 0; i < candidates.length; i++) {
    const v = candidates[i];
    if (v && v !== "" && v !== "N/A" && v !== "null" && v !== "undefined") {
      return v;
    }
  }

  return "N/A";
}

export default function IncidentDetails() {
  const params = useParams();
  const id = params.id;
  const navigate = useNavigate();

  const [incident, setIncident] = useState(null);

  useEffect(function () {
    const ws = new WebSocket(WS_URL);

    ws.onmessage = function (event) {
      const data = JSON.parse(event.data);

      for (let i = 0; i < data.length; i++) {
        if (data[i].id === id) {
          setIncident(data[i]);
          break;
        }
      }
    };

    return function () {
      ws.close();
    };
  }, [id]);

  function exportJSON() {
    if (!incident) return;

    const blob = new Blob([JSON.stringify(incident, null, 2)], {
      type: "application/json",
    });

    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "incident_" + incident.id + ".json";
    a.click();
    URL.revokeObjectURL(url);
  }

  function closeCurrentIncident() {
    if (!incident) return;

    fetch(API_URL + "/incidents/" + incident.id + "/close", {
      method: "PUT",
    })
      .then(function (res) {
        return res.json();
      })
      .then(function (updated) {
        setIncident(updated);
      })
      .catch(function (err) {
        console.error("Close incident error:", err);
      });
  }

  function reopenCurrentIncident() {
    if (!incident) return;

    fetch(API_URL + "/incidents/" + incident.id + "/reopen", {
      method: "PUT",
    })
      .then(function (res) {
        return res.json();
      })
      .then(function (updated) {
        setIncident(updated);
      })
      .catch(function (err) {
        console.error("Reopen incident error:", err);
      });
  }

  const sevColor = incident ? SEVERITY_COLOR[incident.severity] || "#a78bfa" : "#a78bfa";
  const status = incident ? incident.status || "OPEN" : "OPEN";
  const statusColor = STATUS_COLOR[status] || "#9ca3af";
  const targetHost = resolveTargetHost(incident);
  const mitre = incident && incident.mitre ? incident.mitre : {};

  return (
    <Box
      sx={{
        minHeight: "100vh",
        p: 4,
        color: "#fff",
        background: "linear-gradient(135deg, #0f0c29, #302b63, #24243e)",
      }}
    >
      <Card
        sx={{
          ...glass,
          mb: 3,
          border: "1px solid rgba(167,139,250,0.18)",
        }}
      >
        <CardContent sx={{ py: 1.8, "&:last-child": { pb: 1.8 } }}>
          <Stack direction="row" alignItems="center" sx={{ width: "100%" }}>
            <Stack direction="row" alignItems="center" spacing={1.5}>
              <IconButton
                onClick={function () {
                  navigate(-1);
                }}
                sx={{
                  color: "#a78bfa",
                  width: 36,
                  height: 36,
                  "&:hover": {
                    backgroundColor: "rgba(167,139,250,0.12)",
                  },
                }}
              >
                <ArrowBackIcon />
              </IconButton>

              <Typography
                variant="h5"
                fontWeight={800}
                sx={{
                  color: "#ffffff",
                  minWidth: "fit-content",
                }}
              >
                Incident Details
              </Typography>

              {incident && (
                <>
                  <Chip
                    label={incident.severity}
                    size="small"
                    sx={{
                      backgroundColor: sevColor,
                      color: "#fff",
                      fontWeight: 800,
                      height: 26,
                      fontSize: "0.72rem",
                    }}
                  />

                  <Chip
                    label={status}
                    size="small"
                    sx={{
                      backgroundColor: statusColor + "22",
                      color: statusColor,
                      border: "1px solid " + statusColor + "66",
                      fontWeight: 800,
                      height: 26,
                      fontSize: "0.72rem",
                    }}
                  />
                </>
              )}
            </Stack>

            <Box sx={{ flexGrow: 1 }} />

            {incident && (
              <Stack direction="row" spacing={1.2}>
                <Button
                  variant="outlined"
                  size="small"
                  onClick={exportJSON}
                  sx={{
                    height: 36,
                    minWidth: 125,
                    borderRadius: 2,
                    textTransform: "none",
                    fontWeight: 700,
                    color: "#c4b5fd",
                    borderColor: "#7c3aed",
                    fontSize: "0.78rem",
                    "&:hover": {
                      borderColor: "#a78bfa",
                      backgroundColor: "rgba(167,139,250,0.10)",
                    },
                  }}
                >
                  Export JSON
                </Button>

                {status === "CLOSED" ? (
                  <Button
                    variant="contained"
                    size="small"
                    onClick={reopenCurrentIncident}
                    sx={{
                      height: 36,
                      minWidth: 145,
                      borderRadius: 2,
                      textTransform: "none",
                      fontWeight: 800,
                      fontSize: "0.78rem",
                      backgroundColor: "#fbc02d",
                      color: "#111827",
                      boxShadow: "0 0 10px rgba(251,192,45,0.25)",
                      "&:hover": { backgroundColor: "#eab308" },
                    }}
                  >
                    Reopen Incident
                  </Button>
                ) : (
                  <Button
                    variant="contained"
                    size="small"
                    onClick={closeCurrentIncident}
                    sx={{
                      height: 36,
                      minWidth: 145,
                      borderRadius: 2,
                      textTransform: "none",
                      fontWeight: 800,
                      fontSize: "0.78rem",
                      backgroundColor: "#22c55e",
                      color: "#fff",
                      boxShadow: "0 0 10px rgba(34,197,94,0.25)",
                      "&:hover": { backgroundColor: "#16a34a" },
                    }}
                  >
                    Close Incident
                  </Button>
                )}
              </Stack>
            )}
          </Stack>
        </CardContent>
      </Card>

      {!incident ? (
        <Typography sx={{ color: "#cbd5e1" }}>
          Waiting for incident <strong>{id}</strong> via WebSocket...
        </Typography>
      ) : (
        <Stack spacing={3} sx={{ width: "100%" }}>
          <Card sx={glass}>
            <CardContent>
              <SectionTitle>Identification</SectionTitle>
              <Divider sx={{ my: 1, borderColor: "rgba(255,255,255,0.06)" }} />
              <InfoRow label="Incident ID" value={incident.id} mono={true} />
              <InfoRow label="Attack Type" value={incident.type} />
              <InfoRow label="Attacker IP" value={incident.ip} mono={true} />
              <InfoRow label="Target Host" value={targetHost} mono={true} />
              <InfoRow label="Start" value={incident.time_start} />
              <InfoRow label="End" value={incident.time_end} />
              <InfoRow label="Duration" value={incident.duration} />
              <InfoRow label="Alert Count" value={incident.alert_count} />
              <InfoRow label="Status" value={status} />
            </CardContent>
          </Card>

          <Card sx={glass}>
            <CardContent>
              <SectionTitle>Dynamic Priority</SectionTitle>
              <Divider sx={{ my: 1, borderColor: "rgba(255,255,255,0.06)" }} />
              <Box mt={1}>
                <PriorityGauge score={incident.priority} />
              </Box>

              <Box sx={{ mt: 2 }}>
                <InfoRow label="Risk Level" value={incident.risk} />
                <InfoRow
                  label="Confidence"
                  value={incident.confidence ? incident.confidence + "%" : "N/A"}
                />
                <InfoRow label="Engine" value={incident.engine} />
              </Box>
            </CardContent>
          </Card>

          <MachineLearningSection ml={incident.ml} />

          <Card sx={glass}>
            <CardContent>
              <SectionTitle>MITRE ATT&CK Mapping</SectionTitle>
              <Divider sx={{ my: 1, borderColor: "rgba(255,255,255,0.06)" }} />
              <InfoRow label="Tactic" value={mitre.tactic} />
              <InfoRow label="Technique" value={mitre.technique} mono={true} />
              <InfoRow label="Technique Name" value={mitre.technique_name} />
            </CardContent>
          </Card>

          <Card sx={glass}>
            <CardContent>
              <SectionTitle>AI Summary</SectionTitle>
              <Divider sx={{ my: 1, borderColor: "rgba(255,255,255,0.06)" }} />
              <Typography variant="body2" sx={{ color: "#cbd5e1", lineHeight: 1.8, mt: 1 }}>
                {incident.summary || "No summary available."}
              </Typography>
            </CardContent>
          </Card>

          <Card sx={glass}>
            <CardContent>
              <ExplainabilitySection explanation={incident.explanation} />
            </CardContent>
          </Card>

          <Card sx={glass}>
            <CardContent>
              <RecommendedActionsSection actions={incident.recommended_action} />
            </CardContent>
          </Card>

          <Card sx={glass}>
            <CardContent>
              <TimelineSection timeline={incident.timeline} />
            </CardContent>
          </Card>
        </Stack>
      )}
    </Box>
  );
}
