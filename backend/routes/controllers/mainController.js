import * as mainService from "../../services/mainService.js";

const passwd = Deno.env.get("PASSWORD");

const showMain = async ({ request, render, response }) => {
  if (request.method === "POST") {
    let res = "";
    const body = request.body({ type: "json" });
    const data = await body.value;
    const password = data.password;
    if (password === passwd) {
      const key = request.url.searchParams.get("key");
      let type = 3;
      if (key === "master") {
        res = Deno.env.get("MASTERKEY");
        type = 4;
      } else if (key === "hmac") {
        res = Deno.env.get("HMACKEY");
        type = 5;
      }
      mainService.log(request.ip, Math.round(Date.now()/1000), -1, type);
    }
    response.body = res;

    return;
  } else if (request.method === "GET") {
    const statData = {
      logs: [],
      block: [],
    }

    let res = await mainService.getBlocked();
    res.forEach((row) => {
      statData.block.push(row.serialnum);
    });

    res = await mainService.getLogs();
    statData.logs = res;

    for (let i = 0; i < statData.logs.length; i++) {
      let type = "ISSUE";
      switch (statData.logs[i].type) {
        case 0:
          type = "ISSUE";
          break;
        case 1:
          type = "TOP UP";
          break;
        case 2:
          type = "USE";
          break;
        case 3:
          type = "MALICIOUS";
          break;
        case 4:
          type = "MASTER KEY";
          break;
        case 5:
          type = "HMAC KEY";
          break;
        case 6:
          type = "LOG IN";
          break;
        case 7:
          type = "BLOCK";
          break;
        case 8:
          type = "UNBLOCK";
          break;
        default:
          type = "UNKNOWN";
          break;
      }
      if (statData.logs[i].remainuse === -1) {
        statData.logs[i].remainuse = "N/A";
      }
      statData.logs[i].type = type;
    }

    render("main.eta", statData);
    return;
  }
};

const showBlocked = async ({ request, response }) => {
  response.body = "";
  if (request.method === "GET") {
    const res = await mainService.getBlocked();
    for (let i = 0; i < res.length - 1; i++) {
      response.body += res[i].serialnum + "\n";
    }
    if (res.length > 0) {
      response.body += res[res.length - 1].serialnum;
    }
    return;
  } else if (request.method === "POST") {
    const body = request.body({ type: "form" });
    const data = await body.value;
    const serialNum = data.get("serialNum");
    if (serialNum) {
      mainService.log(serialNum, Math.round(Date.now()/1000), -1, 7);
      await mainService.blockCard(serialNum);
    }
    response.redirect("/");
    return;
  }
};

const showUnblocked = async ({ request, response }) => {
  response.body = "";
  if (request.method === "POST") {
    const body = request.body({ type: "form" });
    const data = await body.value;
    const serialNum = data.get("serialNum");
    if (serialNum) {
      mainService.log(serialNum, Math.round(Date.now()/1000), -1, 8);
      await mainService.unblockCard(serialNum);
    }
    response.redirect("/");
    return;
  }
};

const showLogs = async ({ request, response }) => {
  if (request.method === "POST") {
    let res = "";
    const body = request.body({ type: "json" });
    const data = await body.value;
    const password = data.password;
    const cachedLog = data.cachedLog;
    if (password === passwd) {
      cachedLog.split("\n").forEach((line) => {
        if (line) {
          const [serialNum, timestamp, remainUse, type] = line.split(",");
          mainService.log(serialNum, Number(timestamp), Number(remainUse), Number(type));
        }
      });
    }
    response.body = res;
    return;
  }
};


const showLoginForm = async ({ render, request, state, response }) => {
  const login = await state.session.get("login");
  const logout = request.url.searchParams.get("logout");
  if (login) {
    if (logout) {
      await state.session.set("login", false);
      render("login.eta", { error: "Logged out successfully" });
      return;
    }
    response.redirect("/");
  } else {
    render("login.eta");
  }
}

const processLogin = async ({ request, response, state, render }) => {
  const body = request.body({ type: "form" });
  const params = await body.value;

  const passwordMatches = params.get("password") === passwd;

  if (!passwordMatches) {
    render("login.eta", { error: "Your credential is wrong" });
    return;
  }
  mainService.log(request.ip, Math.round(Date.now()/1000), -1, 6);
  await state.session.set("login", true);

  response.redirect("/");
}

export { showMain, showBlocked, showLogs, showUnblocked, showLoginForm, processLogin };
