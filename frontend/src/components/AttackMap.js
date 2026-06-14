import React from "react";
import { MapContainer, TileLayer, CircleMarker, Popup } from "react-leaflet";

export default function AttackMap({ incidents }) {

  return (
    <MapContainer
      center={[30, 0]}
      zoom={2}
      style={{ height: "300px", borderRadius: "10px" }}
    >
      <TileLayer url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" />

      {incidents.map((i, index) => (
        <CircleMarker
          key={index}
          center={[30 + Math.random()*20, 0 + Math.random()*60]} // fake geo
          radius={6}
          color={i.severity === "CRITICAL" ? "red" : "orange"}
        >
          <Popup>
            {i.ip} <br />
            {i.type}
          </Popup>
        </CircleMarker>
      ))}

    </MapContainer>
  );
}
