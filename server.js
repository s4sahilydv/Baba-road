const express = require("express");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;

const SECRET =
  process.env.JWT_SECRET || "brc-change-this-secret";

const ADMIN_EMAIL =
  process.env.ADMIN_EMAIL || "admin@brc.com";

const DB_PATH =
  process.env.DB_PATH || path.join(__dirname, "brc.db");

// ----------------------------------------------------
// DATABASE
// ----------------------------------------------------

const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error("Database connection error:", err.message);
  } else {
    console.log("SQLite database connected");
  }
});

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      phone TEXT,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'user',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS loads (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      from_location TEXT NOT NULL,
      to_location TEXT NOT NULL,
      material TEXT,
      weight TEXT,
      vehicle_type TEXT,
      pickup_date TEXT,
      price TEXT,
      description TEXT,
      status TEXT DEFAULT 'available',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS trucks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      truck_number TEXT NOT NULL,
      truck_type TEXT,
      capacity TEXT,
      driver_name TEXT,
      driver_phone TEXT,
      status TEXT DEFAULT 'Available',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS load_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      load_id INTEGER,
      user_id INTEGER,
      message TEXT,
      status TEXT DEFAULT 'Pending',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(load_id) REFERENCES loads(id),
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);

  db.get(
    `SELECT id FROM users WHERE email = ?`,
    [ADMIN_EMAIL],
    async (err, row) => {
      if (err) {
        console.error(err.message);
        return;
      }

      if (!row) {
        const password = await bcrypt.hash("admin123", 10);

        db.run(
          `
          INSERT INTO users
          (name, email, phone, password, role)
          VALUES (?, ?, ?, ?, ?)
          `,
          [
            "BRC Admin",
            ADMIN_EMAIL,
            "",
            password,
            "admin"
          ],
          (insertErr) => {
            if (insertErr) {
              console.error(
                "Admin creation error:",
                insertErr.message
              );
            } else {
              console.log("Default admin created");
              console.log("Email:", ADMIN_EMAIL);
              console.log("Password: admin123");
            }
          }
        );
      }
    }
  );
});

// ----------------------------------------------------
// MIDDLEWARE
// ----------------------------------------------------

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, "public")));

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role
    },
    SECRET,
    {
      expiresIn: "7d"
    }
  );
}

function auth(req, res, next) {
  const header = req.headers.authorization;

  if (!header) {
    return res.status(401).json({
      success: false,
      message: "Login required"
    });
  }

  const token = header.startsWith("Bearer ")
    ? header.substring(7)
    : header;

  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired token"
    });
  }
}

function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({
      success: false,
      message: "Admin access required"
    });
  }

  next();
}

// ----------------------------------------------------
// HOME
// ----------------------------------------------------

app.get("/", (req, res) => {
  res.sendFile(
    path.join(__dirname, "public", "index.html")
  );
});

// ----------------------------------------------------
// HEALTH CHECK
// ----------------------------------------------------

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    message: "BRC server is running",
    time: new Date().toISOString()
  });
});

// ----------------------------------------------------
// REGISTER
// ----------------------------------------------------

app.post("/api/register", async (req, res) => {
  try {
    const {
      name,
      email,
      phone,
      password
    } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "Name, email and password are required"
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 6 characters"
      });
    }

    const cleanEmail = email.trim().toLowerCase();

    db.get(
      `SELECT id FROM users WHERE email = ?`,
      [cleanEmail],
      async (err, existing) => {
        if (err) {
          return res.status(500).json({
            success: false,
            message: "Database error"
          });
        }

        if (existing) {
          return res.status(409).json({
            success: false,
            message: "Email already registered"
          });
        }

        const hashedPassword =
          await bcrypt.hash(password, 10);

        db.run(
          `
          INSERT INTO users
          (name, email, phone, password, role)
          VALUES (?, ?, ?, ?, ?)
          `,
          [
            name.trim(),
            cleanEmail,
            phone || "",
            hashedPassword,
            "user"
          ],
          function (insertErr) {
            if (insertErr) {
              return res.status(500).json({
                success: false,
                message: insertErr.message
              });
            }

            const user = {
              id: this.lastID,
              name: name.trim(),
              email: cleanEmail,
              role: "user"
            };

            const token = createToken(user);

            res.json({
              success: true,
              message: "Registration successful",
              token,
              user
            });
          }
        );
      }
    );
  } catch (err) {
    console.error(err);

    res.status(500).json({
      success: false,
      message: "Server error"
    });
  }
});

// ----------------------------------------------------
// LOGIN
// ----------------------------------------------------

app.post("/api/login", (req, res) => {
  const {
    email,
    password
  } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      success: false,
      message: "Email and password are required"
    });
  }

  const cleanEmail =
    email.trim().toLowerCase();

  db.get(
    `
    SELECT *
    FROM users
    WHERE email = ?
    `,
    [cleanEmail],
    async (err, user) => {
      if (err) {
        return res.status(500).json({
          success: false,
          message: "Database error"
        });
      }

      if (!user) {
        return res.status(401).json({
          success: false,
          message: "Invalid email or password"
        });
      }

      const valid =
        await bcrypt.compare(
          password,
          user.password
        );

      if (!valid) {
        return res.status(401).json({
          success: false,
          message: "Invalid email or password"
        });
      }

      const safeUser = {
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        role: user.role
      };

      const token =
        createToken(safeUser);

      res.json({
        success: true,
        message: "Login successful",
        token,
        user: safeUser
      });
    }
  );
});

// ----------------------------------------------------
// CURRENT USER
// ----------------------------------------------------

app.get("/api/me", auth, (req, res) => {
  db.get(
    `
    SELECT id, name, email, phone, role, created_at
    FROM users
    WHERE id = ?
    `,
    [req.user.id],
    (err, user) => {
      if (err) {
        return res.status(500).json({
          success: false,
          message: "Database error"
        });
      }

      if (!user) {
        return res.status(404).json({
          success: false,
          message: "User not found"
        });
      }

      res.json({
        success: true,
        user
      });
    }
  );
});

// ----------------------------------------------------
// UPDATE PROFILE
// ----------------------------------------------------

app.put("/api/profile", auth, (req, res) => {
  const {
    name,
    phone
  } = req.body;

  if (!name) {
    return res.status(400).json({
      success: false,
      message: "Name is required"
    });
  }

  db.run(
    `
    UPDATE users
    SET name = ?, phone = ?
    WHERE id = ?
    `,
    [
      name.trim(),
      phone || "",
      req.user.id
    ],
    function (err) {
      if (err) {
        return res.status(500).json({
          success: false,
          message: err.message
        });
      }

      res.json({
        success: true,
        message: "Profile updated"
      });
    }
  );
});

// ----------------------------------------------------
// CHANGE PASSWORD
// ----------------------------------------------------

app.put("/api/change-password", auth, async (req, res) => {
  const {
    oldPassword,
    newPassword
  } = req.body;

  if (!oldPassword || !newPassword) {
    return res.status(400).json({
      success: false,
      message: "Both passwords are required"
    });
  }

  if (newPassword.length < 6) {
    return res.status(400).json({
      success: false,
      message: "New password must be at least 6 characters"
    });
  }

  db.get(
    `SELECT password FROM users WHERE id = ?`,
    [req.user.id],
    async (err, user) => {
      if (err) {
        return res.status(500).json({
          success: false,
          message: "Database error"
        });
      }

      if (!user) {
        return res.status(404).json({
          success: false,
          message: "User not found"
        });
      }

      const valid =
        await bcrypt.compare(
          oldPassword,
          user.password
        );

      if (!valid) {
        return res.status(401).json({
          success: false,
          message: "Old password is incorrect"
        });
      }

      const hashed =
        await bcrypt.hash(
          newPassword,
          10
        );

      db.run(
        `
        UPDATE users
        SET password = ?
        WHERE id = ?
        `,
        [
          hashed,
          req.user.id
        ],
        function (updateErr) {
          if (updateErr) {
            return res.status(500).json({
              success: false,
              message: updateErr.message
            });
          }

          res.json({
            success: true,
            message: "Password changed successfully"
          });
        }
      );
    }
  );
});

// ----------------------------------------------------
// POST LOAD
// ----------------------------------------------------

app.post("/api/loads", auth, (req, res) => {
  const {
    from_location,
    to_location,
    material,
    weight,
    vehicle_type,
    pickup_date,
    price,
    description
  } = req.body;

  if (!from_location || !to_location) {
    return res.status(400).json({
      success: false,
      message: "From and To locations are required"
    });
  }

  db.run(
    `
    INSERT INTO loads
    (
      user_id,
      from_location,
      to_location,
      material,
      weight,
      vehicle_type,
      pickup_date,
      price,
      description,
      status
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `,
    [
      req.user.id,
      from_location.trim(),
      to_location.trim(),
      material || "",
      weight || "",
      vehicle_type || "",
      pickup_date || "",
      price || "",
      description || "",
      "available"
    ],
    function (err) {
      if (err) {
        return res.status(500).json({
          success: false,
          message: err.message
        });
      }

      res.json({
        success: true,
        message: "Load posted successfully",
        loadId: this.lastID
      });
    }
  );
});

// ----------------------------------------------------
// GET ALL LOADS
// ----------------------------------------------------

app.get("/api/loads", (req, res) => {
  const {
    from,
    to,
    vehicle_type,
    status
  } = req.query;

  let sql = `
    SELECT
      loads.*,
      users.name AS owner_name,
      users.phone AS owner_phone
    FROM loads
    LEFT JOIN users
      ON users.id = loads.user_id
    WHERE 1 = 1
  `;

  const params = [];

  if (from) {
    sql += ` AND LOWER(loads.from_location) LIKE LOWER(?)`;
    params.push(`%${from}%`);
  }

  if (to) {
    sql += ` AND LOWER(loads.to_location) LIKE LOWER(?)`;
    params.push(`%${to}%`);
  }

  if (vehicle_type) {
    sql += ` AND LOWER(loads.vehicle_type) LIKE LOWER(?)`;
    params.push(`%${vehicle_type}%`);
  }

  if (status) {
    sql += ` AND loads.status = ?`;
    params.push(status);
  } else {
    sql += ` AND loads.status = 'available'`;
  }

  sql += ` ORDER BY loads.id DESC`;

  db.all(
    sql,
    params,
    (err, rows) => {
      if (err) {
        return res.status(500).json({
          success: false,
          message: err.message
        });
      }

      res.json({
        success: true,
        loads: rows
      });
    }
  );
});

// ----------------------------------------------------
// MY LOADS
// ----------------------------------------------------

app.get("/api/my-loads", auth, (req, res) => {
  db.all(
    `
    SELECT *
    FROM loads
    WHERE user_id = ?
    ORDER BY id DESC
    `,
    [req.user.id],
    (err, rows) => {
      if (err) {
        return res.status(500).json({
          success: false,
          message: err.message
        });
      }

      res.json({
        success: true,
        loads: rows
      });
    }
  );
});

// ----------------------------------------------------
// GET SINGLE LOAD
// ----------------------------------------------------

app.get("/api/loads/:id", (req, res) => {
  db.get(
    `
    SELECT
      loads.*,
      users.name AS owner_name,
      users.email AS owner_email,
      users.phone AS owner_phone
    FROM loads
    LEFT JOIN users
      ON users.id = loads.user_id
    WHERE loads.id = ?
    `,
    [req.params.id],
    (err, load) => {
      if (err) {
        return res.status(500).json({
          success: false,
          message: err.message
        });
      }

      if (!load) {
        return res.status(404).json({
          success: false,
          message: "Load not found"
        });
      }

      res.json({
        success: true,
        load
      });
    }
  );
});

// ----------------------------------------------------
// UPDATE LOAD
// ----------------------------------------------------

app.put("/api/loads/:id", auth, (req, res) => {
  db.get(
    `
    SELECT *
    FROM loads
    WHERE id = ?
    `,
    [req.params.id],
    (err, load) => {
      if (err) {
        return res.status(500).json({
          success: false,
          message: err.message
        });
      }

      if (!load) {
        return res.status(404).json({
          success: false,
          message: "Load not found"
        });
      }

      if (
        load.user_id !== req.user.id &&
        req.user.role !== "admin"
      ) {
        return res.status(403).json({
          success: false,
          message: "Not authorized"
        });
      }

      const {
        from_location,
        to_location,
        material,
        weight,
        vehicle_type,
        pickup_date,
        price,
        description,
        status
      } = req.body;

      db.run(
        `
        UPDATE loads
        SET
          from_location = ?,
          to_location = ?,
          material = ?,
          weight = ?,
          vehicle_type = ?,
          pickup_date = ?,
          price = ?,
          description = ?,
          status = ?
        WHERE id = ?
        `,
        [
          from_location ?? load.from_location,
          to_location ?? load.to_location,
          material ?? load.material,
          weight ?? load.weight,
          vehicle_type ?? load.vehicle_type,
          pickup_date ?? load.pickup_date,
          price ?? load.price,
          description ?? load.description,
          status ?? load.status,
          req.params.id
        ],
        function (updateErr) {
          if (updateErr) {
            return res.status(500).json({
              success: false,
              message: updateErr.message
            });
          }

          res.json({
            success: true,
            message: "Load updated successfully"
          });
        }
      );
    }
  );
});

// ----------------------------------------------------
// DELETE LOAD
// ----------------------------------------------------

app.delete("/api/loads/:id", auth, (req, res) => {
  db.get(
    `
    SELECT user_id
    FROM loads
    WHERE id = ?
    `,
    [req.params.id],
    (err, load) => {
      if (err) {
        return res.status(500).json({
          success: false,
          message: err.message
        });
      }

      if (!load) {
        return res.status(404).json({
          success: false,
          message: "Load not found"
        });
      }

      if (
        load.user_id !== req.user.id &&
        req.user.role !== "admin"
      ) {
        return res.status(403).json({
          success: false,
          message: "Not authorized"
        });
      }

      db.run(
        `DELETE FROM loads WHERE id = ?`,
        [req.params.id],
        function (deleteErr) {
          if (deleteErr) {
            return res.status(500).json({
              success: false,
              message: deleteErr.message
            });
          }

          res.json({
            success: true,
            message: "Load deleted successfully"
          });
        }
      );
    }
  );
});

// ----------------------------------------------------
// ADD TRUCK
// ----------------------------------------------------

app.post("/api/trucks", auth, (req, res) => {
  const {
    truck_number,
    truck_type,
    capacity,
    driver_name,
    driver_phone,
    status
  } = req.body;

  if (!truck_number) {
    return res.status(400).json({
      success: false,
      message: "Truck number is required"
    });
  }

  db.run(
    `
    INSERT INTO trucks
    (
      user_id,
      truck_number,
      truck_type,
      capacity,
      driver_name,
      driver_phone,
      status
    )
    VALUES (?, ?, ?, ?, ?, ?, ?)
    `,
    [
      req.user.id,
      truck_number.trim(),
      truck_type || "",
      capacity || "",
      driver_name || "",
      driver_phone || "",
      status || "Available"
    ],
    function (err) {
      if (err) {
        return res.status(500).json({
          success: false,
          message: err.message
        });
      }

      res.json({
        success: true,
        message: "Truck added successfully"
      });
    }
  );
});

// ----------------------------------------------------
// START SERVER
// ----------------------------------------------------

app.listen(PORT, "0.0.0.0", () => {
  console.log(`BRC server running on port ${PORT}`);
});
