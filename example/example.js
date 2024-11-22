// This is for example

import express from "express";
import bodyParser from "body-parser";
import sqlid from "../lib/index.js";

const app = express();
app.use(bodyParser.json());

// Use the SQL injection guard middleware
app.use(sqlid);

app.post("/data", (req, res) => {
  res.send("Data received safely!");
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});
