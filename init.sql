CREATE EXTENSION IF NOT EXISTS timescaledb;
CREATE TABLE Device (
    DeviceID SERIAL PRIMARY KEY,     
    DeviceName VARCHAR(255) NOT NULL,
    IP_Address VARCHAR(50) NOT NULL,
    CriticalityScore INTEGER
);
CREATE TABLE Threat_Indicator (
    IndicatorID SERIAL PRIMARY KEY,
    IndicatorValue VARCHAR(255) NOT NULL,
    ThreatType VARCHAR(100)
);

CREATE TABLE Admin (
    AdminID SERIAL PRIMARY KEY,
    Username VARCHAR(100) NOT NULL UNIQUE,
    Role VARCHAR(50)
);
CREATE TABLE Metric (
    MetricID SERIAL,
    DeviceID INTEGER REFERENCES Device(DeviceID),
    Timestamp TIMESTAMPTZ NOT NULL,   
    MetricType VARCHAR(100),
    Value DOUBLE PRECISION,
    PRIMARY KEY (MetricID, Timestamp)  
);
CREATE TABLE Log (
    LogID SERIAL,
    DeviceID INTEGER REFERENCES Device(DeviceID),
    Timestamp TIMESTAMPTZ NOT NULL,
    LogMessage TEXT,                   
    PRIMARY KEY (LogID, Timestamp) 
);
CREATE TABLE Alert (
    AlertID SERIAL PRIMARY KEY,
    LogID INTEGER,
    LogTimestamp TIMESTAMPTZ,
    Timestamp TIMESTAMPTZ NOT NULL,
    Priority VARCHAR(50),
    Status VARCHAR(50),
    FinalScore DOUBLE PRECISION,
    FOREIGN KEY (LogID, LogTimestamp) REFERENCES Log(LogID, Timestamp)
);
CREATE TABLE Log_Threat_Match (
    MatchID SERIAL PRIMARY KEY,
    LogID INTEGER,
    LogTimestamp TIMESTAMPTZ,
    IndicatorID INTEGER REFERENCES Threat_Indicator(IndicatorID),
    MatchTimestamp TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (LogID, LogTimestamp) REFERENCES Log(LogID, Timestamp)
);

CREATE TABLE Alert_Assignment (
    AssignmentID SERIAL PRIMARY KEY,
    AlertID INTEGER REFERENCES Alert(AlertID),
    AdminID INTEGER REFERENCES Admin(AdminID),
    AssignmentRole VARCHAR(100)
);