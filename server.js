const express = require("express");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;

const SECRET = process.env.JWT_SECRET || "brc-change-this-secret";
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "admin@brc.com";
const ADMIN_PASSWORD =
  process.env.ADMIN_PASSWORD || "ChangeThisAdminPassword123";

const db = new sqlite3.Database("./brc.db");

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

/* ================= DATABASE ================= */

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      email TEXT UNIQUE,
      password TEXT,
      role TEXT,
      created_at TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS loads(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      from_city TEXT,
      to_city TEXT,
      load_date TEXT,
      truck_type TEXT,
      weight TEXT,
      material TEXT,
      rate TEXT,
      status TEXT DEFAULT 'Open',
      created_at TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS trucks(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      number TEXT,
      type TEXT,
      capacity TEXT,
      status TEXT DEFAULT 'Available'
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS applications(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      load_id INTEGER,
      applicant_id INTEGER,
      truck_id INTEGER,
      status TEXT DEFAULT 'Pending',
      created_at TEXT
    )
  `);
});

/* ================= AUTH ================= */

function auth(req, res, next) {
  try {
    const token = (req.headers.authorization || "").replace("Bearer ", "");

    req.user = jwt.verify(token, SECRET);

    next();
  } catch (e) {
    res.status(401).json({
      error: "Please login"
    });
  }
}

function adminAuth(req, res, next) {
  try {
    const token = (req.headers.authorization || "").replace("Bearer ", "");

    const user = jwt.verify(token, SECRET);

    if (user.role !== "admin") {
      return res.status(403).json({
        error: "Admin access required"
      });
    }

    req.user = user;
    next();
  } catch (e) {
    res.status(401).json({
      error: "Admin login required"
    });
  }
}

/* ================= REGISTER ================= */

app.post("/api/register", async (req, res) => {
  const {
    name,
    email,
    password,
    role = "Transporter"
  } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({
      error: "All fields are required"
    });
  }

  try {
    const hash = await bcrypt.hash(password, 10);

    db.run(
      `
      INSERT INTO users
      (name,email,password,role,created_at)
      VALUES(?,?,?,?,datetime('now'))
      `,
      [
        name,
        email.toLowerCase(),
        hash,
        role
      ],
      function (err) {
        if (err) {
          return res.status(400).json({
            error: "Email already registered"
          });
        }

        const token = jwt.sign(
          {
            id: this.lastID,
            name,
            email: email.toLowerCase(),
            role
          },
          SECRET
        );

        res.json({
          token,
          user: {
            id: this.lastID,
            name,
            email: email.toLowerCase(),
            role
          }
        });
      }
    );
  } catch (e) {
    res.status(500).json({
      error: "Server error"
    });
  }
});

/* ================= LOGIN ================= */

app.post("/api/login", (req, res) => {
  const {
    email,
    password
  } = req.body;

  db.get(
    "SELECT * FROM users WHERE email=?",
    [String(email || "").toLowerCase()],
    async (err, u) => {
      if (
        err ||
        !u ||
        !(await bcrypt.compare(password || "", u.password))
      ) {
        return res.status(401).json({
          error: "Invalid email or password"
        });
      }

      const token = jwt.sign(
        {
          id: u.id,
          name: u.name,
          email: u.email,
          role: u.role
        },
        SECRET
      );

      res.json({
        token,
        user: {
          id: u.id,
          name: u.name,
          email: u.email,
          role: u.role
        }
      });
    }
  );
});

/* ================= ADMIN LOGIN ================= */

app.post("/api/admin/login", (req, res) => {
  const {
    email,
    password
  } = req.body;

  if (
    String(email || "").toLowerCase() !== ADMIN_EMAIL.toLowerCase() ||
    password !== ADMIN_PASSWORD
  ) {
    return res.status(401).json({
      error: "Invalid admin credentials"
    });
  }

  const token = jwt.sign(
    {
      id: 0,
      name: "Administrator",
      email: ADMIN_EMAIL,
      role: "admin"
    },
    SECRET
  );

  res.json({
    token,
    user: {
      name: "Administrator",
      email: ADMIN_EMAIL,
      role: "admin"
    }
  });
});

/* ================= ME ================= */

app.get("/api/me", auth, (req, res) => {
  res.json(req.user);
});

/* ================= GET LOADS ================= */

app.get("/api/loads", (req, res) => {
  let q = `
    SELECT
      l.*,
      u.name AS provider
    FROM loads l
    LEFT JOIN users u
      ON u.id=l.user_id
    WHERE 1=1
  `;

  const p = [];

  if (req.query.from) {
    q += " AND lower(l.from_city) LIKE ?";
    p.push("%" + req.query.from.toLowerCase() + "%");
  }

  if (req.query.to) {
    q += " AND lower(l.to_city) LIKE ?";
    p.push("%" + req.query.to.toLowerCase() + "%");
  }

  if (req.query.type) {
    q += " AND l.truck_type=?";
    p.push(req.query.type);
  }

  q += " ORDER BY l.id DESC";

  db.all(q, p, (e, rows) => {
    res.json(rows || []);
  });
});

/* ================= POST LOAD ================= */

app.post("/api/loads", auth, (req, res) => {
  const x = req.body;

  if (
    !x.from_city ||
    !x.to_city ||
    !x.load_date ||
    !x.truck_type
  ) {
    return res.status(400).json({
      error: "Fill required load details"
    });
  }

  db.run(
    `
    INSERT INTO loads
    (
      user_id,
      from_city,
      to_city,
      load_date,
      truck_type,
      weight,
      material,
      rate,
      created_at
    )
    VALUES(?,?,?,?,?,?,?,?,datetime('now'))
    `,
    [
      req.user.id,
      x.from_city,
      x.to_city,
      x.load_date,
      x.truck_type,
      x.weight || "",
      x.material || "",
      x.rate || ""
    ],
    function (e) {
      if (e) {
        return res.status(500).json({
          error: "Could not post load"
        });
      }

      res.json({
        id: this.lastID,
        message: "Load posted successfully"
      });
    }
  );
});

/* ================= MY LOADS ================= */

app.get("/api/my-loads", auth, (req, res) => {
  db.all(
    `
    SELECT *
    FROM loads
    WHERE user_id=?
    ORDER BY id DESC
    `,
    [req.user.id],
    (e, rows) => {
      res.json(rows || []);
    }
  );
});

/* ================= TRUCKS ================= */

app.post("/api/trucks", auth, (req, res) => {
  const x = req.body;

  if (!x.number || !x.type) {
    return res.status(400).json({
      error: "Truck number and type required"
    });
  }

  db.run(
    `
    INSERT INTO trucks
    (user_id,number,type,capacity)
    VALUES(?,?,?,?)
    `,
    [
      req.user.id,
      x.number,
      x.type,
      x.capacity || ""
    ],
    function (e) {
      if (e) {
        return res.status(500).json({
          error: "Could not add truck"
        });
      }

      res.json({
        id: this.lastID,
        message: "Truck added"
      });
    }
  );
});

app.get("/api/trucks", auth, (req, res) => {
  db.all(
    `
    SELECT *
    FROM trucks
    WHERE user_id=?
    ORDER BY id DESC
    `,
    [req.user.id],
    (e, rows) => {
      res.json(rows || []);
    }
  );
});

app.delete("/api/trucks/:id", auth, (req, res) => {
  db.run(
    `
    DELETE FROM trucks
    WHERE id=? AND user_id=?
    `,
    [
      req.params.id,
      req.user.id
    ],
    () => {
      res.json({
        message: "Deleted"
      });
    }
  );
});

/* ================= APPLY FOR LOAD ================= */

app.post("/api/loads/:id/apply", auth, (req, res) => {
  const loadId = req.params.id;
  const truckId = req.body.truck_id;

  if (!truckId) {
    return res.status(400).json({
      error: "Select a truck"
    });
  }

  db.get(
    `
    SELECT *
    FROM loads
    WHERE id=?
    `,
    [loadId],
    (err, load) => {
      if (err || !load) {
        return res.status(404).json({
          error: "Load not found"
        });
      }

      if (load.status !== "Open") {
        return res.status(400).json({
          error: "This load is not open"
        });
      }

      if (Number(load.user_id) === Number(req.user.id)) {
        return res.status(400).json({
          error: "You cannot apply to your own load"
        });
      }

      db.get(
        `
        SELECT *
        FROM trucks
        WHERE id=? AND user_id=?
        `,
        [
          truckId,
          req.user.id
        ],
        (err2, truck) => {
          if (err2 || !truck) {
            return res.status(400).json({
              error: "Truck not found in your account"
            });
          }

          db.get(
            `
            SELECT *
            FROM applications
            WHERE load_id=?
            AND applicant_id=?
            `,
            [
              loadId,
              req.user.id
            ],
            (err3, existing) => {
              if (existing) {
                return res.status(400).json({
                  error: "You already applied for this load"
                });
              }

              db.run(
                `
                INSERT INTO applications
                (
                  load_id,
                  applicant_id,
                  truck_id,
                  created_at
                )
                VALUES(?,?,?,datetime('now'))
                `,
                [
                  loadId,
                  req.user.id,
                  truckId
                ],
                function (e) {
                  if (e) {
                    return res.status(500).json({
                      error: "Could not submit application"
                    });
                  }

                  res.json({
                    id: this.lastID,
                    message: "Application submitted successfully"
                  });
                }
              );
            }
          );
        }
      );
    }
  );
});

/* ================= MY APPLICATIONS ================= */

app.get("/api/my-applications", auth, (req, res) => {
  db.all(
    `
    SELECT
      a.*,
      l.from_city,
      l.to_city,
      l.load_date,
      l.truck_type,
      l.rate,
      l.status AS load_status,
      t.number AS truck_number,
      t.type AS truck_type_real,
      t.capacity
    FROM applications a
    JOIN loads l
      ON l.id=a.load_id
    JOIN trucks t
      ON t.id=a.truck_id
    WHERE a.applicant_id=?
    ORDER BY a.id DESC
    `,
    [req.user.id],
    (e, rows) => {
      res.json(rows || []);
    }
  );
});

/* ================= LOAD OWNER APPLICATIONS ================= */

app.get("/api/my-load-applications", auth, (req, res) => {
  db.all(
    `
    SELECT
      a.*,
      l.from_city,
      l.to_city,
      l.load_date,
      l.truck_type,
      l.rate,
      l.status AS load_status,
      u.name AS applicant_name,
      u.email AS applicant_email,
      t.number AS truck_number,
      t.type AS truck_type_real,
      t.capacity
    FROM applications a
    JOIN loads l
      ON l.id=a.load_id
    JOIN users u
      ON u.id=a.applicant_id
    JOIN trucks t
      ON t.id=a.truck_id
    WHERE l.user_id=?
    ORDER BY a.id DESC
    `,
    [req.user.id],
    (e, rows) => {
      res.json(rows || []);
    }
  );
});

/* ================= ACCEPT APPLICATION ================= */

app.post("/api/applications/:id/accept", auth, (req, res) => {
  const id = req.params.id;

  db.get(
    `
    SELECT
      a.*,
      l.user_id AS owner_id,
      l.id AS load_id,
      l.status AS load_status
    FROM applications a
    JOIN loads l
      ON l.id=a.load_id
    WHERE a.id=?
    `,
    [id],
    (err, application) => {
      if (err || !application) {
        return res.status(404).json({
          error: "Application not found"
        });
      }

      if (Number(application.owner_id) !== Number(req.user.id)) {
        return res.status(403).json({
          error: "Not allowed"
        });
      }

      if (application.status !== "Pending") {
        return res.status(400).json({
          error: "Application is already processed"
        });
      }

      if (application.load_status !== "Open") {
        return res.status(400).json({
          error: "Load is no longer open"
        });
      }

      db.serialize(() => {
        db.run(
          `
          UPDATE applications
          SET status='Accepted'
          WHERE id=?
          `,
          [id]
        );

        db.run(
          `
          UPDATE loads
          SET status='Assigned'
          WHERE id=?
          `,
          [application.load_id]
        );

        db.run(
          `
          UPDATE applications
          SET status='Rejected'
          WHERE load_id=?
          AND id<>?
          AND status='Pending'
          `,
          [
            application.load_id,
            id
          ],
          () => {
            res.json({
              message: "Application accepted"
            });
          }
        );
      });
    }
  );
});

/* ================= REJECT APPLICATION ================= */

app.post("/api/applications/:id/reject", auth, (req, res) => {
  db.get(
    `
    SELECT
      a.*,
      l.user_id AS owner_id
    FROM applications a
    JOIN loads l
      ON l.id=a.load_id
    WHERE a.id=?
    `,
    [req.params.id],
    (err, application) => {
      if (err || !application) {
        return res.status(404).json({
          error: "Application not found"
        });
      }

      if (Number(application.owner_id) !== Number(req.user.id)) {
        return res.status(403).json({
          error: "Not allowed"
        });
      }

      db.run(
        `
        UPDATE applications
        SET status='Rejected'
        WHERE id=?
        `,
        [req.params.id],
        () => {
          res.json({
            message: "Application rejected"
          });
        }
      );
    }
  );
});

/* ================= STATS ================= */

app.get("/api/stats", auth, (req, res) => {
  db.get(
    `
    SELECT count(*) n
    FROM loads
    WHERE user_id=?
    `,
    [req.user.id],
    (e, a) => {
      db.get(
        `
        SELECT count(*) n
        FROM trucks
        WHERE user_id=?
        `,
        [req.user.id],
        (e, b) => {
          db.get(
            `
            SELECT count(*) n
            FROM loads
            WHERE status='Open'
            `,
            (e, c) => {
              db.get(
                `
                SELECT count(*) n
                FROM applications
                WHERE applicant_id=?
                `,
                [req.user.id],
                (e, d) => {
                  res.json({
                    myLoads: a?.n || 0,
                    trucks: b?.n || 0,
                    openLoads: c?.n || 0,
                    applications: d?.n || 0
                  });
                }
              );
            }
          );
        }
      );
    }
  );
});

/* =====================================================
   ADMIN APIs
   ===================================================== */

/* ================= ADMIN STATS ================= */

app.get("/api/admin/stats", adminAuth, (req, res) => {
  db.get(
    "SELECT count(*) n FROM users",
    (e, users) => {
      db.get(
        "SELECT count(*) n FROM loads",
        (e, loads) => {
          db.get(
            "SELECT count(*) n FROM trucks",
            (e, trucks) => {
              db.get(
                "SELECT count(*) n FROM applications",
                (e, applications) => {
                  res.json({
                    users: users?.n || 0,
                    loads: loads?.n || 0,
                    trucks: trucks?.n || 0,
                    applications: applications?.n || 0
                  });
                }
              );
            }
          );
        }
      );
    }
  );
});

/* ================= ADMIN USERS ================= */

app.get("/api/admin/users", adminAuth, (req, res) => {
  db.all(
    `
    SELECT
      id,
      name,
      email,
      role,
      created_at
    FROM users
    ORDER BY id DESC
    `,
    [],
    (e, rows) => {
      res.json(rows || []);
    }
  );
});

/* ================= ADMIN LOADS ================= */

app.get("/api/admin/loads", adminAuth, (req, res) => {
  db.all(
    `
    SELECT
      l.*,
      u.name AS provider,
      u.email AS provider_email
    FROM loads l
    LEFT JOIN users u
      ON u.id=l.user_id
    ORDER BY l.id DESC
    `,
    [],
    (e, rows) => {
      res.json(rows || []);
    }
  );
});

/* ================= ADMIN TRUCKS ================= */

app.get("/api/admin/trucks", adminAuth, (req, res) => {
  db.all(
    `
    SELECT
      t.*,
      u.name AS owner,
      u.email AS owner_email
    FROM trucks t
    LEFT JOIN users u
      ON u.id=t.user_id
    ORDER BY t.id DESC
    `,
    [],
    (e, rows) => {
      res.json(rows || []);
    }
  );
});

/* ================= ADMIN APPLICATIONS ================= */

app.get("/api/admin/applications", adminAuth, (req, res) => {
  db.all(
    `
    SELECT
      a.*,
      l.from_city,
      l.to_city,
      l.load_date,
      l.rate,
      l.status AS load_status,
      owner.name AS owner_name,
      applicant.name AS applicant_name,
      applicant.email AS applicant_email,
      t.number AS truck_number,
      t.type AS truck_type,
      t.capacity
    FROM applications a
    JOIN loads l
      ON l.id=a.load_id
    LEFT JOIN users owner
      ON owner.id=l.user_id
    LEFT JOIN users applicant
      ON applicant.id=a.applicant_id
    LEFT JOIN trucks t
      ON t.id=a.truck_id
    ORDER BY a.id DESC
    `,
    [],
    (e, rows) => {
      res.json(rows || []);
    }
  );
});

/* ================= ADMIN DELETE USER ================= */

app.delete("/api/admin/users/:id", adminAuth, (req, res) => {
  const id = req.params.id;

  db.serialize(() => {
    db.run(
      `
      DELETE FROM applications
      WHERE applicant_id=?
      `,
      [id]
    );

    db.run(
      `
      DELETE FROM applications
      WHERE load_id IN
      (
        SELECT id FROM loads WHERE user_id=?
      )
      `,
      [id]
    );

    db.run(
      `
      DELETE FROM trucks
      WHERE user_id=?
      `,
      [id]
    );

    db.run(
      `
      DELETE FROM loads
      WHERE user_id=?
      `,
      [id]
    );

    db.run(
      `
      DELETE FROM users
      WHERE id=?
      `,
      [id],
      () => {
        res.json({
          message: "User deleted"
        });
      }
    );
  });
});

/* ================= ADMIN DELETE LOAD ================= */

app.delete("/api/admin/loads/:id", adminAuth, (req, res) => {
  const id = req.params.id;

  db.serialize(() => {
    db.run(
      `
      DELETE FROM applications
      WHERE load_id=?
      `,
      [id]
    );

    db.run(
      `
      DELETE FROM loads
      WHERE id=?
      `,
      [id],
      () => {
        res.json({
          message: "Load deleted"
        });
      }
    );
  });
});

/* ================= ADMIN DELETE TRUCK ================= */

app.delete("/api/admin/trucks/:id", adminAuth, (req, res) => {
  const id = req.params.id;

  db.serialize(() => {
    db.run(
      `
      DELETE FROM applications
      WHERE truc
