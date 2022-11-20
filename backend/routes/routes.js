import { Router } from "../deps.js";
import * as mainController from "./controllers/mainController.js";

const router = new Router();

router.get("/", mainController.showMain);
router.post("/", mainController.showMain);
router.get("/blocked", mainController.showBlocked);
router.post("/blocked", mainController.showBlocked);
router.post("/unblock", mainController.showUnblocked);
router.post("/logs", mainController.showLogs);
router.get("/auth", mainController.showLoginForm);
router.post("/auth", mainController.processLogin);

export { router };
