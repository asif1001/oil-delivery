var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// server/index.ts
import express3 from "express";

// server/routes.ts
import { createServer } from "http";
import express from "express";
import path from "path";

// shared/schema.ts
var schema_exports = {};
__export(schema_exports, {
  branches: () => branches,
  complaints: () => complaints,
  deliveries: () => deliveries,
  insertBranchSchema: () => insertBranchSchema,
  insertComplaintSchema: () => insertComplaintSchema,
  insertDeliverySchema: () => insertDeliverySchema,
  insertOilTankSchema: () => insertOilTankSchema,
  insertOilTypeSchema: () => insertOilTypeSchema,
  oilTanks: () => oilTanks,
  oilTypes: () => oilTypes,
  sessions: () => sessions,
  users: () => users
});
import { sql } from "drizzle-orm";
import {
  index,
  jsonb,
  pgTable,
  timestamp,
  varchar,
  integer,
  boolean,
  text
} from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
var sessions = pgTable(
  "sessions",
  {
    sid: varchar("sid").primaryKey(),
    sess: jsonb("sess").notNull(),
    expire: timestamp("expire").notNull()
  },
  (table) => [index("IDX_session_expire").on(table.expire)]
);
var users = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  email: varchar("email").unique(),
  firstName: varchar("first_name"),
  lastName: varchar("last_name"),
  profileImageUrl: varchar("profile_image_url"),
  role: varchar("role").default("user"),
  // Added role field for permission management
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow()
});
var oilTypes = pgTable("oil_types", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: varchar("name").notNull(),
  color: varchar("color"),
  active: boolean("active").default(true),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow()
});
var branches = pgTable("branches", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: varchar("name").notNull(),
  address: text("address").notNull(),
  contactNo: varchar("contact_no").notNull(),
  active: boolean("active").default(true),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow()
});
var oilTanks = pgTable("oil_tanks", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  branchId: varchar("branch_id").notNull(),
  capacity: integer("capacity").notNull(),
  // in liters
  oilTypeId: varchar("oil_type_id").notNull(),
  currentLevel: integer("current_level").notNull().default(0),
  // in liters
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow()
});
var deliveries = pgTable("deliveries", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  driverUid: varchar("driver_uid").notNull(),
  driverName: varchar("driver_name").notNull(),
  status: varchar("status", { enum: ["loading", "unloading", "completed", "draft"] }).notNull().default("draft"),
  // Loading phase
  oilTypeId: varchar("oil_type_id"),
  loadedOilLiters: integer("loaded_oil_liters"),
  meterReadingPhoto: varchar("meter_reading_photo"),
  loadingTimestamp: timestamp("loading_timestamp"),
  // Unloading phase
  branchId: varchar("branch_id"),
  deliveryOrderNo: varchar("delivery_order_no"),
  startMeterReading: integer("start_meter_reading"),
  tankLevelPhoto: varchar("tank_level_photo"),
  hoseConnectionPhoto: varchar("hose_connection_photo"),
  unloadingTimestamp: timestamp("unloading_timestamp"),
  // Finish phase
  endMeterReading: integer("end_meter_reading"),
  oilSuppliedLiters: integer("oil_supplied_liters"),
  finalTankLevelPhoto: varchar("final_tank_level_photo"),
  completedTimestamp: timestamp("completed_timestamp"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow()
});
var complaints = pgTable("complaints", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  driverUid: varchar("driver_uid").notNull(),
  driverName: varchar("driver_name").notNull(),
  branchId: varchar("branch_id"),
  branchName: varchar("branch_name"),
  oilTankId: varchar("oil_tank_id"),
  description: text("description").notNull(),
  photo: varchar("photo"),
  status: varchar("status", { enum: ["open", "in_progress", "closed"] }).notNull().default("open"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
  resolvedAt: timestamp("resolved_at"),
  adminNotes: text("admin_notes")
});
var insertDeliverySchema = createInsertSchema(deliveries);
var insertComplaintSchema = createInsertSchema(complaints);
var insertOilTypeSchema = createInsertSchema(oilTypes);
var insertBranchSchema = createInsertSchema(branches);
var insertOilTankSchema = createInsertSchema(oilTanks);

// server/db.ts
import { Pool, neonConfig } from "@neondatabase/serverless";
import { drizzle } from "drizzle-orm/neon-serverless";
import ws from "ws";
neonConfig.webSocketConstructor = ws;
if (!process.env.DATABASE_URL) {
  throw new Error(
    "DATABASE_URL must be set. Did you forget to provision a database?"
  );
}
var pool = new Pool({ connectionString: process.env.DATABASE_URL });
var db = drizzle({ client: pool, schema: schema_exports });

// server/storage.ts
import { eq, desc } from "drizzle-orm";
var DatabaseStorage = class {
  // User operations
  // (IMPORTANT) these user operations are mandatory for Replit Auth.
  async getUser(id) {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user;
  }
  async upsertUser(userData) {
    const [user] = await db.insert(users).values(userData).onConflictDoUpdate({
      target: users.id,
      set: {
        ...userData,
        updatedAt: /* @__PURE__ */ new Date()
      }
    }).returning();
    return user;
  }
  // Delivery operations
  async createDelivery(delivery) {
    const [newDelivery] = await db.insert(deliveries).values(delivery).returning();
    return newDelivery;
  }
  async updateDelivery(id, delivery) {
    const [updatedDelivery] = await db.update(deliveries).set({ ...delivery, updatedAt: /* @__PURE__ */ new Date() }).where(eq(deliveries.id, id)).returning();
    return updatedDelivery;
  }
  async getDelivery(id) {
    const [delivery] = await db.select().from(deliveries).where(eq(deliveries.id, id));
    return delivery;
  }
  async getDeliveriesByDriver(driverUid) {
    return db.select().from(deliveries).where(eq(deliveries.driverUid, driverUid)).orderBy(desc(deliveries.createdAt));
  }
  async getAllDeliveries() {
    return db.select().from(deliveries).orderBy(desc(deliveries.createdAt));
  }
  // Complaint operations
  async createComplaint(complaint) {
    const [newComplaint] = await db.insert(complaints).values(complaint).returning();
    return newComplaint;
  }
  async getComplaint(id) {
    const [complaint] = await db.select().from(complaints).where(eq(complaints.id, id));
    return complaint;
  }
  async getComplaintsByDriver(driverUid) {
    return db.select().from(complaints).where(eq(complaints.driverUid, driverUid)).orderBy(desc(complaints.createdAt));
  }
  async getAllComplaints() {
    return db.select().from(complaints).orderBy(desc(complaints.createdAt));
  }
  async updateComplaint(id, complaint) {
    const [updatedComplaint] = await db.update(complaints).set({ ...complaint, updatedAt: /* @__PURE__ */ new Date() }).where(eq(complaints.id, id)).returning();
    return updatedComplaint;
  }
  // Oil Type operations
  async createOilType(oilType) {
    const [newOilType] = await db.insert(oilTypes).values(oilType).returning();
    return newOilType;
  }
  async getOilType(id) {
    const [oilType] = await db.select().from(oilTypes).where(eq(oilTypes.id, id));
    return oilType;
  }
  async getAllOilTypes() {
    return db.select().from(oilTypes).where(eq(oilTypes.active, true));
  }
  async updateOilType(id, oilType) {
    const [updatedOilType] = await db.update(oilTypes).set({ ...oilType, updatedAt: /* @__PURE__ */ new Date() }).where(eq(oilTypes.id, id)).returning();
    return updatedOilType;
  }
  async deleteOilType(id) {
    await db.update(oilTypes).set({ active: false }).where(eq(oilTypes.id, id));
  }
  // Branch operations
  async createBranch(branch) {
    const [newBranch] = await db.insert(branches).values(branch).returning();
    return newBranch;
  }
  async getBranch(id) {
    const [branch] = await db.select().from(branches).where(eq(branches.id, id));
    return branch;
  }
  async getAllBranches() {
    return db.select().from(branches).where(eq(branches.active, true));
  }
  async updateBranch(id, branch) {
    const [updatedBranch] = await db.update(branches).set({ ...branch, updatedAt: /* @__PURE__ */ new Date() }).where(eq(branches.id, id)).returning();
    return updatedBranch;
  }
  async deleteBranch(id) {
    await db.update(branches).set({ active: false }).where(eq(branches.id, id));
  }
  // Oil Tank operations
  async createOilTank(oilTank) {
    const [newOilTank] = await db.insert(oilTanks).values(oilTank).returning();
    return newOilTank;
  }
  async getOilTank(id) {
    const [oilTank] = await db.select().from(oilTanks).where(eq(oilTanks.id, id));
    return oilTank;
  }
  async getOilTanksByBranch(branchId) {
    return db.select().from(oilTanks).where(eq(oilTanks.branchId, branchId));
  }
  async updateOilTank(id, oilTank) {
    const [updatedOilTank] = await db.update(oilTanks).set({ ...oilTank, updatedAt: /* @__PURE__ */ new Date() }).where(eq(oilTanks.id, id)).returning();
    return updatedOilTank;
  }
  async deleteOilTank(id) {
    await db.delete(oilTanks).where(eq(oilTanks.id, id));
  }
};
var storage = new DatabaseStorage();

// server/replitAuth.ts
import * as client from "openid-client";
import { Strategy } from "openid-client/passport";
import passport from "passport";
import session from "express-session";
import memoize from "memoizee";
import connectPg from "connect-pg-simple";
if (!process.env.REPLIT_DOMAINS) {
  throw new Error("Environment variable REPLIT_DOMAINS not provided");
}
var getOidcConfig = memoize(
  async () => {
    return await client.discovery(
      new URL(process.env.ISSUER_URL ?? "https://replit.com/oidc"),
      process.env.REPL_ID
    );
  },
  { maxAge: 3600 * 1e3 }
);
function getSession() {
  const sessionTtl = 7 * 24 * 60 * 60 * 1e3;
  const pgStore = connectPg(session);
  const sessionStore = new pgStore({
    conString: process.env.DATABASE_URL,
    createTableIfMissing: false,
    ttl: sessionTtl,
    tableName: "sessions"
  });
  return session({
    secret: process.env.SESSION_SECRET,
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: true,
      maxAge: sessionTtl
    }
  });
}
function updateUserSession(user, tokens) {
  user.claims = tokens.claims();
  user.access_token = tokens.access_token;
  user.refresh_token = tokens.refresh_token;
  user.expires_at = user.claims?.exp;
}
async function upsertUser(claims) {
  await storage.upsertUser({
    id: claims["sub"],
    email: claims["email"],
    firstName: claims["first_name"],
    lastName: claims["last_name"],
    profileImageUrl: claims["profile_image_url"]
  });
}
async function setupAuth(app2) {
  app2.set("trust proxy", 1);
  app2.use(getSession());
  app2.use(passport.initialize());
  app2.use(passport.session());
  const config = await getOidcConfig();
  const verify = async (tokens, verified) => {
    const user = {};
    updateUserSession(user, tokens);
    await upsertUser(tokens.claims());
    verified(null, user);
  };
  for (const domain of process.env.REPLIT_DOMAINS.split(",")) {
    const strategy = new Strategy(
      {
        name: `replitauth:${domain}`,
        config,
        scope: "openid email profile offline_access",
        callbackURL: `https://${domain}/api/callback`
      },
      verify
    );
    passport.use(strategy);
  }
  passport.serializeUser((user, cb) => cb(null, user));
  passport.deserializeUser((user, cb) => cb(null, user));
  app2.get("/api/login", (req, res, next) => {
    passport.authenticate(`replitauth:${req.hostname}`, {
      prompt: "login consent",
      scope: ["openid", "email", "profile", "offline_access"]
    })(req, res, next);
  });
  app2.get("/api/callback", (req, res, next) => {
    passport.authenticate(`replitauth:${req.hostname}`, {
      successReturnToOrRedirect: "/",
      failureRedirect: "/api/login"
    })(req, res, next);
  });
  app2.get("/api/logout", (req, res) => {
    console.log("Logout endpoint called");
    req.logout((err) => {
      if (err) {
        console.error("Logout error:", err);
        return res.status(500).json({ error: "Logout failed" });
      }
      if (req.session) {
        req.session.destroy((err2) => {
          if (err2) {
            console.error("Session destroy error:", err2);
          }
          res.clearCookie("connect.sid", { path: "/" });
          res.clearCookie("session", { path: "/" });
          console.log("\u2705 User logged out successfully, redirecting to login");
          res.redirect("/");
        });
      } else {
        res.clearCookie("connect.sid", { path: "/" });
        res.clearCookie("session", { path: "/" });
        console.log("\u2705 User logged out successfully, redirecting to login");
        res.redirect("/");
      }
    });
  });
}
var isAuthenticated = async (req, res, next) => {
  const user = req.user;
  if (!req.isAuthenticated() || !user.expires_at) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  const now = Math.floor(Date.now() / 1e3);
  if (now <= user.expires_at) {
    return next();
  }
  const refreshToken = user.refresh_token;
  if (!refreshToken) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }
  try {
    const config = await getOidcConfig();
    const tokenResponse = await client.refreshTokenGrant(config, refreshToken);
    updateUserSession(user, tokenResponse);
    return next();
  } catch (error) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }
};

// server/firebase.ts
var getOilTypes = async () => {
  return [
    {
      id: "bGTwva2sKFalkYRUSqt",
      name: "Min Oil",
      color: "#22c55e",
      active: true,
      createdAt: "2025-08-14T15:16:33.000Z"
    },
    {
      id: "BxPJhZEBMTZd4s7DRwj",
      name: "Syn Oil",
      color: "#3b82f6",
      active: true,
      createdAt: "2025-08-14T15:16:31.000Z"
    }
  ];
};
var getBranches = async () => {
  return [
    {
      id: "NYH6ZJe3cCQZtWBzYjB",
      name: "ARAD TSC",
      address: "ARAD TOYOTA SERVICE STATION",
      contactNo: "33239783",
      active: true,
      createdAt: "2025-08-14T15:18:16.000Z",
      oilTanks: [
        {
          capacity: 12e3,
          oilTypeId: 0
        }
      ]
    }
  ];
};
var getActiveLoadSessions = async (driverId) => {
  try {
    const mockSessions = [
      {
        id: "load_001",
        loadDriverId: "DhCpjywb0cNi0A66R9YHrR9aut02",
        loadDriverName: "kannan.n",
        oilTypeId: "bGTwva2sKFalkYRUSqt",
        oilTypeName: "Min Oil",
        totalLoadedLiters: 2500,
        remainingLiters: 2500,
        loadTimestamp: (/* @__PURE__ */ new Date()).toISOString(),
        loadMeterReading: 15e4,
        loadPhoto: "load_photo_url",
        truckPlateNumber: "BH-12345",
        status: "active",
        createdAt: (/* @__PURE__ */ new Date()).toISOString(),
        updatedAt: (/* @__PURE__ */ new Date()).toISOString()
      }
    ];
    return driverId ? mockSessions.filter((s) => s.loadDriverId === driverId) : mockSessions;
  } catch (error) {
    console.error("Error fetching load sessions:", error);
    throw error;
  }
};
var getDeliveryOrders = async (loadSessionId) => {
  try {
    const mockOrders = [
      {
        id: "del_001",
        orderNumber: "ORD-2025-001",
        loadSessionId: "load_001",
        branchId: "NYH6ZJe3cCQZtWBzYjB",
        branchName: "ARAD TSC",
        requestedLiters: 1e3,
        status: "pending"
      },
      {
        id: "del_002",
        orderNumber: "ORD-2025-002",
        loadSessionId: "load_001",
        branchId: "NYH6ZJe3cCQZtWBzYjB",
        branchName: "ARAD TSC",
        requestedLiters: 1500,
        status: "pending"
      }
    ];
    return loadSessionId ? mockOrders.filter((o) => o.loadSessionId === loadSessionId) : mockOrders;
  } catch (error) {
    console.error("Error fetching delivery orders:", error);
    throw error;
  }
};
var createDeliveryOrder = async (orderData) => {
  try {
    const newOrder = {
      id: `del_${Date.now()}`,
      orderNumber: `ORD-${(/* @__PURE__ */ new Date()).getFullYear()}-${String(Date.now()).slice(-3)}`,
      ...orderData,
      status: "pending",
      createdAt: (/* @__PURE__ */ new Date()).toISOString(),
      updatedAt: (/* @__PURE__ */ new Date()).toISOString()
    };
    console.log("Created delivery order:", newOrder);
    return newOrder;
  } catch (error) {
    console.error("Error creating delivery order:", error);
    throw error;
  }
};
var updateLoadSessionRemaining = async (loadSessionId, deliveredLiters) => {
  try {
    console.log(`Updating load session ${loadSessionId}: delivered ${deliveredLiters}L`);
    return {
      loadSessionId,
      deliveredLiters,
      updatedAt: (/* @__PURE__ */ new Date()).toISOString()
    };
  } catch (error) {
    console.error("Error updating load session:", error);
    throw error;
  }
};

// server/routes.ts
import { z } from "zod";
var updateRoleSchema = z.object({
  role: z.enum(["admin", "user", "driver", "business"])
});
async function registerRoutes(app2) {
  app2.use(express.static(path.join(process.cwd(), "public")));
  app2.get("/logo.png", (req, res) => {
    res.sendFile(path.join(process.cwd(), "public", "logo.png"));
  });
  app2.get("/api/proxy-photo", async (req, res) => {
    const photoUrl = req.query.url;
    if (!photoUrl) {
      return res.status(400).json({ error: "Photo URL is required" });
    }
    try {
      const response = await fetch(photoUrl);
      if (!response.ok) {
        return res.status(response.status).json({
          error: `Failed to fetch photo: ${response.statusText}`
        });
      }
      const contentType = response.headers.get("content-type") || "image/jpeg";
      const buffer = await response.arrayBuffer();
      res.set({
        "Content-Type": contentType,
        "Content-Length": buffer.byteLength.toString(),
        "Cache-Control": "public, max-age=3600"
      });
      res.send(Buffer.from(buffer));
    } catch (error) {
      console.error("Photo proxy error:", error);
      res.status(500).json({ error: "Failed to fetch photo" });
    }
  });
  await setupAuth(app2);
  app2.get("/api/firebase/user/:userId", isAuthenticated, async (req, res) => {
    try {
      const userId = req.params.userId;
      const userProfile = {
        id: userId,
        email: "kannan.n@ekkanoo.com.bh",
        displayName: "Kannan N",
        role: "driver",
        active: true
      };
      res.json(userProfile);
    } catch (error) {
      console.error("Error fetching user data:", error);
      res.status(500).json({ error: "Failed to fetch user data" });
    }
  });
  app2.get("/api/firebase/transactions", isAuthenticated, async (req, res) => {
    try {
      res.json([]);
    } catch (error) {
      console.error("Error fetching transactions:", error);
      res.status(500).json({ error: "Failed to fetch transactions" });
    }
  });
  app2.get("/api/auth/user", async (req, res) => {
    try {
      if (!req.user || !req.isAuthenticated()) {
        console.log("\u274C No authenticated session found");
        return res.status(401).json({ message: "Not authenticated" });
      }
      const userData = {
        id: req.user.claims.sub,
        email: req.user.claims.email,
        firstName: req.user.claims.first_name,
        lastName: req.user.claims.last_name,
        displayName: `${req.user.claims.first_name} ${req.user.claims.last_name}`,
        role: req.user.claims.email?.toLowerCase().includes("admin") ? "admin" : "driver",
        active: true
      };
      console.log("\u2705 Authenticated user found:", userData.email);
      res.json(userData);
    } catch (error) {
      console.error("Error fetching user:", error);
      res.status(500).json({ message: "Failed to fetch user" });
    }
  });
  app2.patch("/api/users/:id/role", isAuthenticated, async (req, res) => {
    try {
      const currentUser = await storage.getUser(req.user.claims.sub);
      if (!currentUser || currentUser.role !== "admin") {
        return res.status(403).json({ message: "Admin access required" });
      }
      const { id } = req.params;
      const { role } = updateRoleSchema.parse(req.body);
      const updatedUser = { id, role };
      console.log(`Updated user ${id} role to ${role}`);
      res.json(updatedUser);
    } catch (error) {
      console.error("Error updating user role:", error);
      res.status(500).json({ message: "Failed to update user role" });
    }
  });
  app2.get("/api/stats", isAuthenticated, async (req, res) => {
    try {
      const currentUser = await storage.getUser(req.user.claims.sub);
      if (!currentUser) {
        return res.status(404).json({ message: "User not found" });
      }
      const stats = {
        totalUsers: 248,
        activeDrivers: 52,
        businesses: 18,
        revenue: "$12.4K"
      };
      res.json(stats);
    } catch (error) {
      console.error("Error fetching stats:", error);
      res.status(500).json({ message: "Failed to fetch stats" });
    }
  });
  app2.get("/api/activities", isAuthenticated, async (req, res) => {
    try {
      const currentUser = await storage.getUser(req.user.claims.sub);
      if (!currentUser) {
        return res.status(404).json({ message: "User not found" });
      }
      const activities = [
        {
          id: "1",
          type: "delivery",
          description: "New delivery completed",
          timestamp: /* @__PURE__ */ new Date(),
          user: "John Doe"
        }
      ];
      res.json(activities);
    } catch (error) {
      console.error("Error fetching activities:", error);
      res.status(500).json({ message: "Failed to fetch activities" });
    }
  });
  app2.get("/api/oil-types", async (req, res) => {
    try {
      const oilTypes2 = await getOilTypes();
      res.json(oilTypes2);
    } catch (error) {
      console.error("Error fetching oil types:", error);
      res.status(500).json({ message: "Failed to fetch oil types" });
    }
  });
  app2.get("/api/branches", async (req, res) => {
    try {
      const branches2 = await getBranches();
      res.json(branches2);
    } catch (error) {
      console.error("Error fetching branches:", error);
      res.status(500).json({ message: "Failed to fetch branches" });
    }
  });
  app2.get("/api/load-sessions", async (req, res) => {
    try {
      const driverUid = "DhCpjywb0cNi0A66R9YHrR9aut02";
      const sessions2 = await getActiveLoadSessions(driverUid);
      res.json(sessions2);
    } catch (error) {
      console.error("Error fetching load sessions:", error);
      res.status(500).json({ error: "Failed to fetch load sessions" });
    }
  });
  app2.post("/api/load-sessions", async (req, res) => {
    try {
      const driverUid = "DhCpjywb0cNi0A66R9YHrR9aut02";
      const loadSessionId = `LOAD-${Date.now()}`;
      const session2 = {
        id: loadSessionId,
        ...req.body,
        loadDriverId: driverUid,
        loadDriverName: "kannan.n",
        createdAt: (/* @__PURE__ */ new Date()).toISOString(),
        status: "active"
      };
      console.log("Load session created:", session2);
      res.json(session2);
    } catch (error) {
      console.error("Error creating load session:", error);
      res.status(500).json({ error: "Failed to create load session" });
    }
  });
  app2.get("/api/delivery-orders", async (req, res) => {
    try {
      const loadSessionId = req.query.loadSessionId;
      const deliveryOrders = await getDeliveryOrders(loadSessionId);
      res.json(deliveryOrders);
    } catch (error) {
      console.error("Error fetching delivery orders:", error);
      res.status(500).json({ message: "Failed to fetch delivery orders" });
    }
  });
  app2.post("/api/delivery-orders", isAuthenticated, async (req, res) => {
    try {
      const driverUid = req.user.claims.sub;
      const order = await createDeliveryOrder({ ...req.body, deliveryDriverId: driverUid });
      res.json(order);
    } catch (error) {
      console.error("Error creating delivery order:", error);
      res.status(500).json({ error: "Failed to create delivery order" });
    }
  });
  app2.post("/api/deliveries/complete", async (req, res) => {
    try {
      const { loadSessionId, deliveredLiters, deliveryData } = req.body;
      await updateLoadSessionRemaining(loadSessionId, deliveredLiters);
      const transaction = {
        id: `txn_${Date.now()}`,
        ...deliveryData,
        driverUid: req.user.claims.sub,
        timestamp: (/* @__PURE__ */ new Date()).toISOString()
      };
      console.log("Delivery completed:", transaction);
      res.json({ success: true, transaction });
    } catch (error) {
      console.error("Error completing delivery:", error);
      res.status(500).json({ error: "Failed to complete delivery" });
    }
  });
  app2.post("/api/deliveries", isAuthenticated, async (req, res) => {
    try {
      const driverUid = req.user.claims.sub;
      const deliveryData = insertDeliverySchema.parse({ ...req.body, driverUid });
      const delivery = await storage.createDelivery(deliveryData);
      res.json(delivery);
    } catch (error) {
      console.error("Error creating delivery:", error);
      res.status(500).json({ message: "Failed to create delivery" });
    }
  });
  app2.get("/api/deliveries/my", isAuthenticated, async (req, res) => {
    try {
      const driverUid = req.user.claims.sub;
      const deliveries2 = await storage.getDeliveriesByDriver(driverUid);
      res.json(deliveries2);
    } catch (error) {
      console.error("Error fetching deliveries:", error);
      res.status(500).json({ message: "Failed to fetch deliveries" });
    }
  });
  app2.get("/api/deliveries", isAuthenticated, async (req, res) => {
    try {
      const currentUser = await storage.getUser(req.user.claims.sub);
      if (!currentUser || currentUser.role !== "admin") {
        return res.status(403).json({ message: "Admin access required" });
      }
      const deliveries2 = await storage.getAllDeliveries();
      res.json(deliveries2);
    } catch (error) {
      console.error("Error fetching deliveries:", error);
      res.status(500).json({ message: "Failed to fetch deliveries" });
    }
  });
  app2.put("/api/deliveries/:id", isAuthenticated, async (req, res) => {
    try {
      const { id } = req.params;
      const driverUid = req.user.claims.sub;
      const existingDelivery = await storage.getDelivery(id);
      if (!existingDelivery) {
        return res.status(404).json({ message: "Delivery not found" });
      }
      const currentUser = await storage.getUser(driverUid);
      if (existingDelivery.driverUid !== driverUid && currentUser?.role !== "admin") {
        return res.status(403).json({ message: "Access denied" });
      }
      const updateData = insertDeliverySchema.partial().parse(req.body);
      const delivery = await storage.updateDelivery(id, updateData);
      res.json(delivery);
    } catch (error) {
      console.error("Error updating delivery:", error);
      res.status(500).json({ message: "Failed to update delivery" });
    }
  });
  app2.post("/api/complaints", isAuthenticated, async (req, res) => {
    try {
      const driverUid = req.user.claims.sub;
      const complaintData = insertComplaintSchema.parse({ ...req.body, driverUid });
      const complaint = await storage.createComplaint(complaintData);
      res.json(complaint);
    } catch (error) {
      console.error("Error creating complaint:", error);
      res.status(500).json({ message: "Failed to create complaint" });
    }
  });
  app2.get("/api/complaints/my", isAuthenticated, async (req, res) => {
    try {
      const driverUid = req.user.claims.sub;
      const complaints2 = await storage.getComplaintsByDriver(driverUid);
      res.json(complaints2);
    } catch (error) {
      console.error("Error fetching complaints:", error);
      res.status(500).json({ message: "Failed to fetch complaints" });
    }
  });
  app2.get("/api/complaints", isAuthenticated, async (req, res) => {
    try {
      const currentUser = await storage.getUser(req.user.claims.sub);
      if (!currentUser || currentUser.role !== "admin") {
        return res.status(403).json({ message: "Admin access required" });
      }
      const complaints2 = await storage.getAllComplaints();
      res.json(complaints2);
    } catch (error) {
      console.error("Error fetching complaints:", error);
      res.status(500).json({ message: "Failed to fetch complaints" });
    }
  });
  app2.put("/api/complaints/:id", isAuthenticated, async (req, res) => {
    try {
      const currentUser = await storage.getUser(req.user.claims.sub);
      if (!currentUser || currentUser.role !== "admin") {
        return res.status(403).json({ message: "Admin access required" });
      }
      const { id } = req.params;
      const updateData = insertComplaintSchema.partial().parse(req.body);
      const complaint = await storage.updateComplaint(id, updateData);
      res.json(complaint);
    } catch (error) {
      console.error("Error updating complaint:", error);
      res.status(500).json({ message: "Failed to update complaint" });
    }
  });
  app2.get("/api/oil-types", isAuthenticated, async (req, res) => {
    try {
      const oilTypes2 = await storage.getAllOilTypes();
      res.json(oilTypes2);
    } catch (error) {
      console.error("Error fetching oil types:", error);
      res.status(500).json({ message: "Failed to fetch oil types" });
    }
  });
  app2.post("/api/oil-types", isAuthenticated, async (req, res) => {
    try {
      const currentUser = await storage.getUser(req.user.claims.sub);
      if (!currentUser || currentUser.role !== "admin") {
        return res.status(403).json({ message: "Admin access required" });
      }
      const oilTypeData = insertOilTypeSchema.parse(req.body);
      const oilType = await storage.createOilType(oilTypeData);
      res.json(oilType);
    } catch (error) {
      console.error("Error creating oil type:", error);
      res.status(500).json({ message: "Failed to create oil type" });
    }
  });
  app2.get("/api/branches", isAuthenticated, async (req, res) => {
    try {
      const branches2 = await storage.getAllBranches();
      res.json(branches2);
    } catch (error) {
      console.error("Error fetching branches:", error);
      res.status(500).json({ message: "Failed to fetch branches" });
    }
  });
  app2.post("/api/branches", isAuthenticated, async (req, res) => {
    try {
      const currentUser = await storage.getUser(req.user.claims.sub);
      if (!currentUser || currentUser.role !== "admin") {
        return res.status(403).json({ message: "Admin access required" });
      }
      const branchData = insertBranchSchema.parse(req.body);
      const branch = await storage.createBranch(branchData);
      res.json(branch);
    } catch (error) {
      console.error("Error creating branch:", error);
      res.status(500).json({ message: "Failed to create branch" });
    }
  });
  app2.get("/api/deliveries/recent", async (req, res) => {
    try {
      const recentDeliveries = [
        {
          id: "del_001",
          deliveryOrderNo: "ORD-2025-001",
          branchName: "ARAD TSC",
          oilTypeName: "Min Oil",
          oilSuppliedLiters: 1500,
          status: "completed",
          createdAt: (/* @__PURE__ */ new Date("2025-01-14T14:30:00Z")).toISOString(),
          photos: {
            tankLevelBefore: "url1",
            hoseConnection: "url2",
            tankLevelAfter: "url3"
          }
        },
        {
          id: "del_002",
          deliveryOrderNo: "ORD-2025-002",
          branchName: "ARAD TSC",
          oilTypeName: "Syn Oil",
          oilSuppliedLiters: 1e3,
          status: "completed",
          createdAt: (/* @__PURE__ */ new Date("2025-01-13T16:45:00Z")).toISOString(),
          photos: {
            tankLevelBefore: "url4",
            hoseConnection: "url5",
            tankLevelAfter: "url6"
          }
        },
        {
          id: "del_003",
          deliveryOrderNo: "ORD-2025-003",
          branchName: "SAAR TSC",
          oilTypeName: "Min Oil",
          oilSuppliedLiters: 800,
          status: "completed",
          createdAt: (/* @__PURE__ */ new Date("2025-01-12T11:20:00Z")).toISOString(),
          photos: {
            tankLevelBefore: "url7",
            hoseConnection: "url8",
            tankLevelAfter: "url9"
          }
        }
      ];
      res.json(recentDeliveries);
    } catch (error) {
      console.error("Error fetching recent deliveries:", error);
      res.status(500).json({ error: "Failed to fetch recent deliveries" });
    }
  });
  app2.get("/api/tank-balance", async (req, res) => {
    try {
      const tankBalance = {
        totalCapacity: 25e3,
        // Total tank capacity in liters
        currentLevel: 18750,
        // Current oil level in liters
        percentage: 75,
        // 75% full
        lastUpdated: (/* @__PURE__ */ new Date()).toISOString(),
        oilType: "Min Oil"
      };
      res.json(tankBalance);
    } catch (error) {
      console.error("Error fetching tank balance:", error);
      res.status(500).json({ error: "Failed to fetch tank balance" });
    }
  });
  const httpServer = createServer(app2);
  return httpServer;
}

// server/vite.ts
import express2 from "express";
import fs from "fs";
import path3 from "path";
import { createServer as createViteServer, createLogger } from "vite";

// vite.config.ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path2 from "path";
import runtimeErrorOverlay from "@replit/vite-plugin-runtime-error-modal";
var vite_config_default = defineConfig({
  plugins: [
    react(),
    runtimeErrorOverlay(),
    ...process.env.NODE_ENV !== "production" && process.env.REPL_ID !== void 0 ? [
      await import("@replit/vite-plugin-cartographer").then(
        (m) => m.cartographer()
      )
    ] : []
  ],
  resolve: {
    alias: {
      "@": path2.resolve(import.meta.dirname, "client", "src"),
      "@shared": path2.resolve(import.meta.dirname, "shared"),
      "@assets": path2.resolve(import.meta.dirname, "attached_assets")
    }
  },
  root: path2.resolve(import.meta.dirname, "client"),
  build: {
    outDir: path2.resolve(import.meta.dirname, "dist/public"),
    emptyOutDir: true
  },
  server: {
    fs: {
      strict: true,
      deny: ["**/.*"]
    }
  }
});

// server/vite.ts
import { nanoid } from "nanoid";
var viteLogger = createLogger();
function log(message, source = "express") {
  const formattedTime = (/* @__PURE__ */ new Date()).toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true
  });
  console.log(`${formattedTime} [${source}] ${message}`);
}
async function setupVite(app2, server) {
  const serverOptions = {
    middlewareMode: true,
    hmr: { server },
    allowedHosts: true
  };
  const vite = await createViteServer({
    ...vite_config_default,
    configFile: false,
    customLogger: {
      ...viteLogger,
      error: (msg, options) => {
        viteLogger.error(msg, options);
        process.exit(1);
      }
    },
    server: serverOptions,
    appType: "custom"
  });
  app2.use(vite.middlewares);
  app2.use("*", async (req, res, next) => {
    const url = req.originalUrl;
    try {
      const clientTemplate = path3.resolve(
        import.meta.dirname,
        "..",
        "client",
        "index.html"
      );
      let template = await fs.promises.readFile(clientTemplate, "utf-8");
      template = template.replace(
        `src="/src/main.tsx"`,
        `src="/src/main.tsx?v=${nanoid()}"`
      );
      const page = await vite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(page);
    } catch (e) {
      vite.ssrFixStacktrace(e);
      next(e);
    }
  });
}
function serveStatic(app2) {
  const distPath = path3.resolve(import.meta.dirname, "public");
  if (!fs.existsSync(distPath)) {
    throw new Error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`
    );
  }
  app2.use(express2.static(distPath));
  app2.use("*", (_req, res) => {
    res.sendFile(path3.resolve(distPath, "index.html"));
  });
}

// server/index.ts
var app = express3();
app.use(express3.json());
app.use(express3.urlencoded({ extended: false }));
app.use((req, res, next) => {
  const start = Date.now();
  const path4 = req.path;
  let capturedJsonResponse = void 0;
  const originalResJson = res.json;
  res.json = function(bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };
  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path4.startsWith("/api")) {
      let logLine = `${req.method} ${path4} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }
      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "\u2026";
      }
      log(logLine);
    }
  });
  next();
});
(async () => {
  const server = await registerRoutes(app);
  app.use((err, _req, res, _next) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";
    res.status(status).json({ message });
    throw err;
  });
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }
  const port = parseInt(process.env.PORT || "5000", 10);
  server.listen({
    port,
    host: "0.0.0.0",
    reusePort: true
  }, () => {
    log(`serving on port ${port}`);
  });
})();
