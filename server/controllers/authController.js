const bcrypt = require("bcryptjs");

module.exports = {
  register: async (req, res) => {
    const { username, password, isAdmin } = req.body;
    const db = req.app.get("db");

    const result = await db.get_user([username]);
    const existingUser = result[0];

    if (existingUser) {
      return res.status(409).send("Username taken");
    }

    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(password, salt);

    const registeredUser = await db.register_user([isAdmin, username, hash]);
    const user = registeredUser[0];

    req.session.user = {
      isAdmin: user.is_admin,
      username: user.username,
      id: user.id,
    };
    return res.status(201).send(req.session.user);
  },
  login: async (req, res) => {
    const { username, password } = req.body;
    const db = req.app.get("db");

    const result = await db.get_user([username]),
      existingUser = result[0];

    if (!existingUser) {
      return res.status(401).send("User does not exist");
    }

    const authenticated = bcrypt.compareSync(password, existingUser.hash);

    if (!authenticated) {
      return res.status(403).send("Username and password do not match");
    }

    req.session.user = {
      username: existingUser.username,
      isAdmin: existingUser.is_admin,
      id: existingUser.id,
    };

    return res.status(200).send(req.session.user);
  },
  logout: (req, res) => {
    req.session.destroy();

    res.sendStatus(200);
  },
};
