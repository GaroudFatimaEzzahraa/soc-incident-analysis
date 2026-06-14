import React from "react";
import { useNavigate } from "react-router-dom";
import {
  Table, TableBody, TableCell, TableHead, TableRow
} from "@mui/material";

export default function IncidentTable({ incidents }) {

  const navigate = useNavigate();

  return (
    <Table>
      <TableHead>
        <TableRow>
          <TableCell>ID</TableCell>
          <TableCell>Type</TableCell>
          <TableCell>IP</TableCell>
          <TableCell>Severity</TableCell>
          <TableCell>Score</TableCell>
        </TableRow>
      </TableHead>

      <TableBody>
        {incidents.map((i) => (
          <TableRow
            key={i.id}
            onClick={() => navigate(`/incident/${i.id}`)}
            style={{ cursor: "pointer" }}
          >
            <TableCell>{i.id}</TableCell>
            <TableCell>{i.type}</TableCell>
            <TableCell>{i.ip}</TableCell>
            <TableCell>{i.severity}</TableCell>
            <TableCell>{i.score}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
