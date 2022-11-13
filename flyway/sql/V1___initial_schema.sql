CREATE TABLE blocked (
  serialNum TEXT PRIMARY KEY
);

CREATE TABLE logs (
  id SERIAL PRIMARY KEY,
  serialNum TEXT NOT NULL,
  timestamp INT NOT NULL,
  remainUse INT NOT NULL,
  type INT NOT NULL
);
