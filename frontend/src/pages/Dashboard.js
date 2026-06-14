import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Box, Typography, Card, CardContent,
  Table, TableHead, TableRow, TableCell, TableBody,
  Chip, LinearProgress, Stack,
} from "@mui/material";
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, BarChart, Bar, CartesianGrid,
} from "recharts";

const WS_URL = "ws://192.168.137.130:8000/ws/incidents";

const glass = {
  background: "rgba(255,255,255,0.05)",
  borderRadius: 3,
  backdropFilter: "blur(10px)",
};

const cardBorder = (color) => ({
  ...glass,
  border: "1px solid " + color,
  boxShadow: "0 0 12px " + color + "44",
});

const head = { color: "#a5b4fc", fontWeight: 700 };
const cell = { color: "#fff" };
const cardText = { color: "#ffffff" };

const SEVERITY_COLOR = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  MEDIUM: "#fbc02d",
  LOW: "#22c55e",
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

function PriorityCell({ score }) {
  var color = priorityColor(score || 0);

  return (
    <Stack direction="row" alignItems="center" spacing={1}>
      <Typography variant="body2" fontWeight={700} sx={{ color: color, minWidth: 28 }}>
        {score || "0"}
      </Typography>
      <LinearProgress
        variant="determinate"
        value={score || 0}
        sx={{
          width: 50,
          height: 6,
          borderRadius: 3,
          backgroundColor: "rgba(255,255,255,0.08)",
          "& .MuiLinearProgress-bar": {
            backgroundColor: color,
            borderRadius: 3,
          },
        }}
      />
    </Stack>
  );
}

function MLScoreCell({ incident }) {
  var score = incident.ml ? incident.ml.anomaly_score || 0 : 0;
  var color = mlColor(score);

  if (!incident.ml) {
    return <Typography sx={{ color: "#64748b" }}>N/A</Typography>;
  }

  return (
    <Stack direction="row" alignItems="center" spacing={1}>
      <Typography variant="body2" fontWeight={700} sx={{ color: color, minWidth: 35 }}>
        {score}%
      </Typography>
      <LinearProgress
        variant="determinate"
        value={score}
        sx={{
          width: 55,
          height: 6,
          borderRadius: 3,
          backgroundColor: "rgba(255,255,255,0.08)",
          "& .MuiLinearProgress-bar": {
            backgroundColor: color,
            borderRadius: 3,
          },
        }}
      />
    </Stack>
  );
}

function ChartTitle({ children }) {
  return (
    <Typography mb={2} fontWeight={700} sx={{ color: "#fff" }}>
      {children}
    </Typography>
  );
}

export default function Dashboard() {
  const [incidents, setIncidents] = useState([]);
  const [connected, setConnected] = useState(false);
  const [chartData, setChartData] = useState([]);
  const navigate = useNavigate();

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

      setChartData(function (prev) {
        return prev.slice(-20).concat([
          {
            time: new Date().toLocaleTimeString(),
            total: unique.length,
            open: unique.filter(function (i) {
              return (i.status || "OPEN") === "OPEN";
            }).length,
            anomalous: unique.filter(function (i) {
              return i.ml && i.ml.prediction === "ANOMALOUS";
            }).length,
          },
        ]);
      });
    };

    return function () {
      ws.close();
    };
  }, []);

  var sorted = incidents.slice().sort(function (a, b) {
    return (b.priority || 0) - (a.priority || 0);
  });

  var stats = {
    total: incidents.length,
    critical: incidents.filter(function (i) { return i.severity === "CRITICAL"; }).length,
    high: incidents.filter(function (i) { return i.severity === "HIGH"; }).length,
    medium: incidents.filter(function (i) { return i.severity === "MEDIUM"; }).length,
    low: incidents.filter(function (i) { return i.severity === "LOW"; }).length,
    open: incidents.filter(function (i) { return (i.status || "OPEN") === "OPEN"; }).length,
    closed: incidents.filter(function (i) { return i.status === "CLOSED"; }).length,
    anomalous: incidents.filter(function (i) {
      return i.ml && i.ml.prediction === "ANOMALOUS";
    }).length,
  };

  var severityData = [
    { name: "Critical", value: stats.critical, color: "#ef4444" },
    { name: "High", value: stats.high, color: "#f97316" },
    { name: "Medium", value: stats.medium, color: "#fbc02d" },
    { name: "Low", value: stats.low, color: "#22c55e" },
  ].filter(function (item) {
    return item.value > 0;
  });

  var statusData = [
    { name: "Open", value: stats.open, color: "#ef4444" },
    { name: "Closed", value: stats.closed, color: "#22c55e" },
  ].filter(function (item) {
    return item.value > 0;
  });

  var mlData = [
    { name: "Normal", value: incidents.filter(function (i) {
      return i.ml && i.ml.prediction === "NORMAL";
    }).length, color: "#22c55e" },
    { name: "Anomalous", value: stats.anomalous, color: "#ec4899" },
    { name: "Unknown", value: incidents.filter(function (i) {
      return !i.ml || i.ml.prediction === "UNKNOWN";
    }).length, color: "#64748b" },
  ].filter(function (item) {
    return item.value > 0;
  });

  var attackMap = {};
  incidents.forEach(function (inc) {
    var type = inc.type || "Unknown";
    attackMap[type] = (attackMap[type] || 0) + 1;
  });

  var attackData = Object.keys(attackMap).map(function (key) {
    return {
      type: key,
      count: attackMap[key],
    };
  });

  var topPriorityData = sorted.slice(0, 5).map(function (inc) {
    return {
      id: inc.id,
      priority: inc.priority || 0,
    };
  });

  var topMLData = incidents
    .slice()
    .sort(function (a, b) {
      var aScore = a.ml ? a.ml.anomaly_score || 0 : 0;
      var bScore = b.ml ? b.ml.anomaly_score || 0 : 0;
      return bScore - aScore;
    })
    .slice(0, 5)
    .map(function (inc) {
      return {
        id: inc.id,
        score: inc.ml ? inc.ml.anomaly_score || 0 : 0,
      };
    });

  return (
    <Box
      sx={{
        minHeight: "100vh",
        p: 4,
        color: "#fff",
        background: "linear-gradient(135deg, #0f0c29, #302b63, #24243e)",
      }}
    >
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <Typography variant="h4" fontWeight={700} sx={{ color: "#fff" }}>
          SOC Platform
        </Typography>

        <Typography sx={{ color: connected ? "#22c55e" : "#ef4444", fontWeight: "bold" }}>
          {connected ? "LIVE CONNECTED" : "OFFLINE"}
        </Typography>
      </Box>

      <Box
        sx={{
          display: "grid",
          gridTemplateColumns: {
            xs: "1fr",
            sm: "repeat(2, 1fr)",
            md: "repeat(4, 1fr)",
            lg: "repeat(7, 1fr)",
          },
          gap: 2,
          mt: 2,
        }}
      >
        <Card sx={cardBorder("#6366f1")}>
          <CardContent sx={cardText}>
            <Typography sx={cardText}>Total</Typography>
            <Typography variant="h3" fontWeight={800} sx={cardText}>{stats.total}</Typography>
          </CardContent>
        </Card>

        <Card sx={cardBorder("#ef4444")}>
          <CardContent sx={cardText}>
            <Typography sx={cardText}>Critical</Typography>
            <Typography variant="h3" fontWeight={800} sx={cardText}>{stats.critical}</Typography>
          </CardContent>
        </Card>

        <Card sx={cardBorder("#f97316")}>
          <CardContent sx={cardText}>
            <Typography sx={cardText}>High</Typography>
            <Typography variant="h3" fontWeight={800} sx={cardText}>{stats.high}</Typography>
          </CardContent>
        </Card>

        <Card sx={cardBorder("#fbc02d")}>
          <CardContent sx={cardText}>
            <Typography sx={cardText}>Medium</Typography>
            <Typography variant="h3" fontWeight={800} sx={cardText}>{stats.medium}</Typography>
          </CardContent>
        </Card>

        <Card sx={cardBorder("#22c55e")}>
          <CardContent sx={cardText}>
            <Typography sx={cardText}>Low</Typography>
            <Typography variant="h3" fontWeight={800} sx={cardText}>{stats.low}</Typography>
          </CardContent>
        </Card>

        <Card sx={cardBorder("#38bdf8")}>
          <CardContent sx={cardText}>
            <Typography sx={cardText}>Open</Typography>
            <Typography variant="h3" fontWeight={800} sx={cardText}>{stats.open}</Typography>
          </CardContent>
        </Card>

        <Card sx={cardBorder("#ec4899")}>
          <CardContent sx={cardText}>
            <Typography sx={cardText}>Anomalous</Typography>
            <Typography variant="h3" fontWeight={800} sx={cardText}>{stats.anomalous}</Typography>
          </CardContent>
        </Card>
      </Box>

      <Box
        sx={{
          display: "grid",
          gridTemplateColumns: {
            xs: "1fr",
            lg: "2fr 1fr",
          },
          gap: 3,
          mt: 3,
        }}
      >
        <Card sx={glass}>
          <CardContent>
            <ChartTitle>Threat Evolution</ChartTitle>

            <ResponsiveContainer width="100%" height={260}>
              <LineChart data={chartData}>
                <CartesianGrid stroke="rgba(255,255,255,0.08)" />
                <XAxis dataKey="time" stroke="#ccc" />
                <YAxis stroke="#ccc" allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    background: "#1e1b4b",
                    border: "1px solid rgba(255,255,255,0.1)",
                    color: "#fff",
                  }}
                />
                <Line type="monotone" dataKey="total" stroke="#a78bfa" strokeWidth={3} dot={false} />
                <Line type="monotone" dataKey="open" stroke="#38bdf8" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="anomalous" stroke="#ec4899" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card sx={glass}>
          <CardContent>
            <ChartTitle>ML Behavior Distribution</ChartTitle>

            <ResponsiveContainer width="100%" height={260}>
              <PieChart>
                <Pie
                  data={mlData}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={55}
                  outerRadius={85}
                  paddingAngle={4}
                  label
                >
                  {mlData.map(function (entry, index) {
                    return <Cell key={index} fill={entry.color} />;
                  })}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: "#1e1b4b",
                    border: "1px solid rgba(255,255,255,0.1)",
                    color: "#fff",
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </Box>

      <Box
        sx={{
          display: "grid",
          gridTemplateColumns: {
            xs: "1fr",
            lg: "1fr 1fr 1fr",
          },
          gap: 3,
          mt: 3,
        }}
      >
        <Card sx={glass}>
          <CardContent>
            <ChartTitle>Severity Distribution</ChartTitle>

            <ResponsiveContainer width="100%" height={230}>
              <PieChart>
                <Pie
                  data={severityData}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={45}
                  outerRadius={75}
                  paddingAngle={4}
                  label
                >
                  {severityData.map(function (entry, index) {
                    return <Cell key={index} fill={entry.color} />;
                  })}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: "#1e1b4b",
                    border: "1px solid rgba(255,255,255,0.1)",
                    color: "#fff",
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card sx={glass}>
          <CardContent>
            <ChartTitle>Status Overview</ChartTitle>

            <ResponsiveContainer width="100%" height={230}>
              <PieChart>
                <Pie
                  data={statusData}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={45}
                  outerRadius={75}
                  paddingAngle={4}
                  label
                >
                  {statusData.map(function (entry, index) {
                    return <Cell key={index} fill={entry.color} />;
                  })}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: "#1e1b4b",
                    border: "1px solid rgba(255,255,255,0.1)",
                    color: "#fff",
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card sx={glass}>
          <CardContent>
            <ChartTitle>Attack Types</ChartTitle>

            <ResponsiveContainer width="100%" height={230}>
              <BarChart data={attackData}>
                <CartesianGrid stroke="rgba(255,255,255,0.08)" />
                <XAxis dataKey="type" stroke="#ccc" tick={{ fontSize: 10 }} />
                <YAxis stroke="#ccc" allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    background: "#1e1b4b",
                    border: "1px solid rgba(255,255,255,0.1)",
                    color: "#fff",
                  }}
                />
                <Bar dataKey="count" fill="#a78bfa" radius={[6, 6, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </Box>

      <Box
        sx={{
          display: "grid",
          gridTemplateColumns: {
            xs: "1fr",
            lg: "1fr 1fr",
          },
          gap: 3,
          mt: 3,
        }}
      >
        <Card sx={glass}>
          <CardContent>
            <ChartTitle>Top Priority Incidents</ChartTitle>

            <ResponsiveContainer width="100%" height={230}>
              <BarChart data={topPriorityData}>
                <CartesianGrid stroke="rgba(255,255,255,0.08)" />
                <XAxis dataKey="id" stroke="#ccc" tick={{ fontSize: 10 }} />
                <YAxis stroke="#ccc" domain={[0, 100]} />
                <Tooltip
                  contentStyle={{
                    background: "#1e1b4b",
                    border: "1px solid rgba(255,255,255,0.1)",
                    color: "#fff",
                  }}
                />
                <Bar dataKey="priority" fill="#fbc02d" radius={[6, 6, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card sx={glass}>
          <CardContent>
            <ChartTitle>Top ML Anomaly Scores</ChartTitle>

            <ResponsiveContainer width="100%" height={230}>
              <BarChart data={topMLData}>
                <CartesianGrid stroke="rgba(255,255,255,0.08)" />
                <XAxis dataKey="id" stroke="#ccc" tick={{ fontSize: 10 }} />
                <YAxis stroke="#ccc" domain={[0, 100]} />
                <Tooltip
                  contentStyle={{
                    background: "#1e1b4b",
                    border: "1px solid rgba(255,255,255,0.1)",
                    color: "#fff",
                  }}
                />
                <Bar dataKey="score" fill="#ec4899" radius={[6, 6, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </Box>

      <Card sx={{ mt: 3, ...glass }}>
        <CardContent>
          <Typography mb={2} sx={{ color: "#fff" }}>
            Live Incidents
            <Typography component="span" variant="caption" sx={{ color: "#c4b5fd" }} ml={1}>
              (sorted by priority)
            </Typography>
          </Typography>

          <Table>
            <TableHead>
              <TableRow>
                <TableCell sx={head}>ID</TableCell>
                <TableCell sx={head}>Type</TableCell>
                <TableCell sx={head}>IP</TableCell>
                <TableCell sx={head}>Target</TableCell>
                <TableCell sx={head}>Status</TableCell>
                <TableCell sx={head}>Severity</TableCell>
                <TableCell sx={head}>Priority</TableCell>
                <TableCell sx={head}>ML Score</TableCell>
                <TableCell sx={head}>Confidence</TableCell>
                <TableCell sx={head}>Alerts</TableCell>
              </TableRow>
            </TableHead>

            <TableBody>
              {sorted.map(function (inc) {
                var status = inc.status || "OPEN";
                var statusColor = status === "CLOSED" ? "#22c55e" : "#ef4444";

                return (
                  <TableRow
                    key={inc.id}
                    onClick={function () {
                      navigate("/incident/" + inc.id);
                    }}
                    sx={{
                      cursor: "pointer",
                      "&:hover": { background: "rgba(167,139,250,0.1)" },
                    }}
                  >
                    <TableCell sx={{ ...cell, fontFamily: "monospace" }}>{inc.id}</TableCell>
                    <TableCell sx={cell}>{inc.type}</TableCell>

                    <TableCell sx={{ ...cell, color: "#38bdf8", fontFamily: "monospace" }}>
                      {inc.ip}
                    </TableCell>

                    <TableCell sx={{ ...cell, color: "#e5e7eb", fontFamily: "monospace" }}>
                      {inc.target_agent || "-"}
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
                          fontSize: "0.7rem",
                        }}
                      />
                    </TableCell>

                    <TableCell>
                      <Chip
                        label={inc.severity}
                        size="small"
                        sx={{
                          backgroundColor: SEVERITY_COLOR[inc.severity] || "#555",
                          color: "#fff",
                          fontWeight: 700,
                          fontSize: "0.7rem",
                        }}
                      />
                    </TableCell>

                    <TableCell>
                      <PriorityCell score={inc.priority} />
                    </TableCell>

                    <TableCell>
                      <MLScoreCell incident={inc} />
                    </TableCell>

                    <TableCell sx={cell}>
                      {inc.confidence ? inc.confidence + "%" : "N/A"}
                    </TableCell>

                    <TableCell sx={cell}>
                      {inc.alert_count || "N/A"}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </Box>
  );
}
