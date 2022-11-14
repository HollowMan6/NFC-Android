import * as mainService from "../../services/mainService.js";

const passwd = "l54G*b,_Qtm85qo/Js&ec809@sZ2A$"

const showMain = async ({ request, render, response }) => {
  if (request.method === "POST") {
    let res = "";
    const body = request.body({ type: "json" });
    const data = await body.value;
    const password = data.password;
    if (password === passwd) {
      const key = request.url.searchParams.get("key");
      if (key === "master") {
        res = "UqKrQZ!YM94@2hdJ";
      } else if (key === "hmac") {
        res = "QsmaRpTnSHx77lTX";
      }
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


const showLoginForm = ({ render }) => {
  render("login.eta");
}

const processLogin = async ({ request, response, state, render }) => {
  const body = request.body({ type: "form" });
  const params = await body.value;

  const passwordMatches = params.get("password") === passwd;

  if (!passwordMatches) {
      render("login.eta", { error: "Your credential is wrong" });
      return;
  }
  await state.session.set("login", true);

  response.redirect("/");
}

export { showMain, showBlocked, showLogs, showUnblocked, showLoginForm, processLogin };
