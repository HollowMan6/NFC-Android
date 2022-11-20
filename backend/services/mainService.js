const blocked = new Set()
const logs = []

const getBlocked = async () => {
    return blocked
}

const blockCard = async (serialNum) => {
    blocked.add(serialNum)
}

const unblockCard = async (serialNum) => {
    blocked.delete(serialNum)
}

const log = async (serialnum, timestamp, remainuse, type) => {
    logs.push({
        serialnum, timestamp, remainuse, type
    })
}

const getLogs = async () => {
    return logs
}

export { getBlocked, blockCard, log, getLogs, unblockCard }