import { executeQuery } from "../database/database.js";

const getBlocked = async () => {
    const res = await executeQuery(
        "SELECT serialNum FROM blocked"
    )

    return res.rows
}

const blockCard = async (serialNum) => {
    return await executeQuery(
        "INSERT INTO blocked (serialNum) VALUES ($serialNum)",
        { serialNum },
    )
}

const unblockCard = async (serialNum) => {
    return await executeQuery(
        "DELETE FROM blocked WHERE serialNum = $serialNum",
        { serialNum },
    )
}

const log = async (serialNum, timestamp, remainUse, type) => {
    return await executeQuery(
        "INSERT INTO logs (serialNum, timestamp, remainUse, type) VALUES ($serialNum, $timestamp, $remainUse, $type)",
        { serialNum, timestamp, remainUse, type },
    )
}

const getLogs = async () => {
    const res = await executeQuery(
        "SELECT * FROM logs ORDER BY timestamp DESC"
    )

    return res.rows
}

const clearLogs = async (minute) => {
    return await executeQuery(
        "DELETE FROM logs WHERE timestamp < $timestamp",
        { timestamp: Math.round(Date.now() / 1000) - minute * 60 },
    )
}

export { getBlocked, blockCard, log, getLogs, clearLogs, unblockCard }