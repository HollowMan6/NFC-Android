const unrestrictedPaths = {
  "/": ["POST"],
  "/blocked": ["GET"],
  "/logs": ["POST"],
  "/auth": ["GET", "POST"],
};

const authenticateMiddleware = async (context, next) => {
  const login = await context.state.session.get("login");

  if (!login && !(context.request.url.pathname in unrestrictedPaths && unrestrictedPaths[context.request.url.pathname].some((e) => e === context.request.method))) {
    context.response.redirect("/auth");
  } else {
    await next();
  }
};

export { authenticateMiddleware };
