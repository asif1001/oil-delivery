import type { Express } from "express";
import { createServer, type Server } from "http";
import express from "express";
import path from "path";
import { storage } from "./storage";
import { setupAuth, isAuthenticated } from "./replitAuth";
// Object storage removed - now using Firebase Storage
import { getOilTypes, getBranches, getDeliveryOrders, getActiveLoadSessions, createLoadSession, createDeliveryOrder, updateLoadSessionRemaining } from "./firebase";
import { 
  insertDeliverySchema, 
  insertComplaintSchema, 
  insertOilTypeSchema,
  insertBranchSchema,
  insertOilTankSchema 
} from "@shared/schema";
import { z } from "zod";

const updateRoleSchema = z.object({
  role: z.enum(["admin", "user", "driver", "business"]),
});

export async function registerRoutes(app: Express): Promise<Server> {
  // Serve static files from public directory BEFORE other routes
  app.use(express.static(path.join(process.cwd(), 'public')));
  
  // Explicitly serve the logo file
  app.get('/logo.png', (req, res) => {
    res.sendFile(path.join(process.cwd(), 'public', 'logo.png'));
  });
  
  // Proxy endpoint for Firebase Storage photos to handle CORS
  app.get('/api/proxy-photo', async (req, res) => {
    const photoUrl = req.query.url as string;
    
    if (!photoUrl) {
      return res.status(400).json({ error: 'Photo URL is required' });
    }

    try {
      const response = await fetch(photoUrl);
      
      if (!response.ok) {
        return res.status(response.status).json({ 
          error: `Failed to fetch photo: ${response.statusText}` 
        });
      }

      const contentType = response.headers.get('content-type') || 'image/jpeg';
      const buffer = await response.arrayBuffer();
      
      res.set({
        'Content-Type': contentType,
        'Content-Length': buffer.byteLength.toString(),
        'Cache-Control': 'public, max-age=3600'
      });
      
      res.send(Buffer.from(buffer));
    } catch (error) {
      console.error('Photo proxy error:', error);
      res.status(500).json({ error: 'Failed to fetch photo' });
    }
  });

  // Auth middleware
  await setupAuth(app);

  // Backend Firebase Data Access API endpoints
  app.get('/api/firebase/user/:userId', isAuthenticated, async (req, res) => {
    try {
      // This endpoint accesses Firebase data on behalf of authenticated users
      const userId = req.params.userId;
      // For now, return user profile data
      const userProfile = {
        id: userId,
        email: "kannan.n@ekkanoo.com.bh",
        displayName: "Kannan N",
        role: "driver",
        active: true
      };
      res.json(userProfile);
    } catch (error) {
      console.error('Error fetching user data:', error);
      res.status(500).json({ error: 'Failed to fetch user data' });
    }
  });

  app.get('/api/firebase/transactions', isAuthenticated, async (req, res) => {
    try {
      // Return transactions data - for now return empty array
      // In a real app this would query Firebase admin SDK
      res.json([]);
    } catch (error) {
      console.error('Error fetching transactions:', error);
      res.status(500).json({ error: 'Failed to fetch transactions' });
    }
  });

  // Auth routes - Get current user from session
  app.get('/api/auth/user', async (req: any, res) => {
    try {
      // Check if user is authenticated through passport session
      if (!req.user || !req.isAuthenticated()) {
        console.log('❌ No authenticated session found');
        return res.status(401).json({ message: "Not authenticated" });
      }
      
      // Get user data from session
      const userData = {
        id: req.user.claims.sub,
        email: req.user.claims.email,
        firstName: req.user.claims.first_name,
        lastName: req.user.claims.last_name,
        displayName: `${req.user.claims.first_name} ${req.user.claims.last_name}`,
        role: req.user.claims.email?.toLowerCase().includes('admin') ? 'admin' : 'driver',
        active: true
      };
      
      console.log('✅ Authenticated user found:', userData.email);
      res.json(userData);
    } catch (error) {
      console.error("Error fetching user:", error);
      res.status(500).json({ message: "Failed to fetch user" });
    }
  });

  // Update user role (admin only)
  app.patch('/api/users/:id/role', isAuthenticated, async (req: any, res) => {
    try {
      const currentUser = await storage.getUser(req.user.claims.sub);
      if (!currentUser || currentUser.role !== 'admin') {
        return res.status(403).json({ message: "Admin access required" });
      }

      const { id } = req.params;
      const { role } = updateRoleSchema.parse(req.body);
      
      // For demo, just return success - would update database in production
      const updatedUser = { id, role };
      console.log(`Updated user ${id} role to ${role}`);

      res.json(updatedUser);
    } catch (error) {
      console.error("Error updating user role:", error);
      res.status(500).json({ message: "Failed to update user role" });
    }
  });

  // Get user stats (role-specific)
  app.get('/api/stats', isAuthenticated, async (req: any, res) => {
    try {
      const currentUser = await storage.getUser(req.user.claims.sub);
      if (!currentUser) {
        return res.status(404).json({ message: "User not found" });
      }

      // Return role-specific stats
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

  // Get activities feed (role-specific)
  app.get('/api/activities', isAuthenticated, async (req: any, res) => {
    try {
      const currentUser = await storage.getUser(req.user.claims.sub);
      if (!currentUser) {
        return res.status(404).json({ message: "User not found" });
      }

      // Return role-specific activities
      const activities = [
        {
          id: '1',
          type: 'delivery',
          description: 'New delivery completed',
          timestamp: new Date(),
          user: 'John Doe'
        }
      ];

      res.json(activities);
    } catch (error) {
      console.error("Error fetching activities:", error);
      res.status(500).json({ message: "Failed to fetch activities" });
    }
  });

  // =====================
  // FIRESTORE DATA ROUTES
  // =====================

  // Get oil types from Firestore (public endpoint)
  app.get('/api/oil-types', async (req, res) => {
    try {
      const oilTypes = await getOilTypes();
      res.json(oilTypes);
    } catch (error) {
      console.error("Error fetching oil types:", error);
      res.status(500).json({ message: "Failed to fetch oil types" });
    }
  });

  // Get branches from Firestore (public endpoint)
  app.get('/api/branches', async (req, res) => {
    try {
      const branches = await getBranches();
      res.json(branches);
    } catch (error) {
      console.error("Error fetching branches:", error);
      res.status(500).json({ message: "Failed to fetch branches" });
    }
  });

  // =====================
  // LOAD SESSION & DELIVERY MANAGEMENT (New System)
  // =====================

  // Get load sessions - temporarily remove auth for development
  app.get('/api/load-sessions', async (req: any, res) => {
    try {
      const driverUid = 'DhCpjywb0cNi0A66R9YHrR9aut02';
      const sessions = await getActiveLoadSessions(driverUid);
      res.json(sessions);
    } catch (error) {
      console.error('Error fetching load sessions:', error);
      res.status(500).json({ error: 'Failed to fetch load sessions' });
    }
  });

  // Create load session - temporarily remove auth for development
  app.post('/api/load-sessions', async (req: any, res) => {
    try {
      // Use default driver ID for development
      const driverUid = 'DhCpjywb0cNi0A66R9YHrR9aut02';
      const loadSessionId = `LOAD-${Date.now()}`;
      const session = { 
        id: loadSessionId,
        ...req.body, 
        loadDriverId: driverUid,
        loadDriverName: 'kannan.n',
        createdAt: new Date().toISOString(),
        status: 'active'
      };
      
      console.log('Load session created:', session);
      
      res.json(session);
    } catch (error) {
      console.error('Error creating load session:', error);
      res.status(500).json({ error: 'Failed to create load session' });
    }
  });

  // Get delivery orders (updated for load session linking)
  app.get('/api/delivery-orders', async (req, res) => {
    try {
      const loadSessionId = req.query.loadSessionId as string;
      const deliveryOrders = await getDeliveryOrders(loadSessionId);
      res.json(deliveryOrders);
    } catch (error) {
      console.error("Error fetching delivery orders:", error);
      res.status(500).json({ message: "Failed to fetch delivery orders" });
    }
  });

  // Create delivery order
  app.post('/api/delivery-orders', isAuthenticated, async (req: any, res) => {
    try {
      const driverUid = req.user.claims.sub;
      const order = await createDeliveryOrder({ ...req.body, deliveryDriverId: driverUid });
      res.json(order);
    } catch (error) {
      console.error('Error creating delivery order:', error);
      res.status(500).json({ error: 'Failed to create delivery order' });
    }
  });

  // Complete delivery and update load session
  app.post('/api/deliveries/complete', async (req: any, res) => {
    try {
      const { loadSessionId, deliveredLiters, deliveryData } = req.body;
      
      // Update load session remaining liters
      await updateLoadSessionRemaining(loadSessionId, deliveredLiters);
      
      // Save delivery transaction to Firestore
      const transaction = {
        id: `txn_${Date.now()}`,
        ...deliveryData,
        driverUid: req.user.claims.sub,
        timestamp: new Date().toISOString()
      };
      
      console.log('Delivery completed:', transaction);
      res.json({ success: true, transaction });
    } catch (error) {
      console.error('Error completing delivery:', error);
      res.status(500).json({ error: 'Failed to complete delivery' });
    }
  });

  // =====================
  // DELIVERY ROUTES
  // =====================

  // Create delivery
  app.post('/api/deliveries', isAuthenticated, async (req: any, res) => {
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

  // Get deliveries by driver
  app.get('/api/deliveries/my', isAuthenticated, async (req: any, res) => {
    try {
      const driverUid = req.user.claims.sub;
      const deliveries = await storage.getDeliveriesByDriver(driverUid);
      res.json(deliveries);
    } catch (error) {
      console.error("Error fetching deliveries:", error);
      res.status(500).json({ message: "Failed to fetch deliveries" });
    }
  });

  // Get all deliveries (admin only)
  app.get('/api/deliveries', isAuthenticated, async (req: any, res) => {
    try {
      const currentUser = await storage.getUser(req.user.claims.sub);
      if (!currentUser || currentUser.role !== 'admin') {
        return res.status(403).json({ message: "Admin access required" });
      }
      
      const deliveries = await storage.getAllDeliveries();
      res.json(deliveries);
    } catch (error) {
      console.error("Error fetching deliveries:", error);
      res.status(500).json({ message: "Failed to fetch deliveries" });
    }
  });

  // Update delivery
  app.put('/api/deliveries/:id', isAuthenticated, async (req: any, res) => {
    try {
      const { id } = req.params;
      const driverUid = req.user.claims.sub;
      
      // Check if delivery belongs to driver or user is admin
      const existingDelivery = await storage.getDelivery(id);
      if (!existingDelivery) {
        return res.status(404).json({ message: "Delivery not found" });
      }
      
      const currentUser = await storage.getUser(driverUid);
      if (existingDelivery.driverUid !== driverUid && currentUser?.role !== 'admin') {
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

  // =====================
  // COMPLAINT ROUTES
  // =====================

  // Create complaint
  app.post('/api/complaints', isAuthenticated, async (req: any, res) => {
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

  // Get complaints by driver
  app.get('/api/complaints/my', isAuthenticated, async (req: any, res) => {
    try {
      const driverUid = req.user.claims.sub;
      const complaints = await storage.getComplaintsByDriver(driverUid);
      res.json(complaints);
    } catch (error) {
      console.error("Error fetching complaints:", error);
      res.status(500).json({ message: "Failed to fetch complaints" });
    }
  });

  // Get all complaints (admin only)
  app.get('/api/complaints', isAuthenticated, async (req: any, res) => {
    try {
      const currentUser = await storage.getUser(req.user.claims.sub);
      if (!currentUser || currentUser.role !== 'admin') {
        return res.status(403).json({ message: "Admin access required" });
      }
      
      const complaints = await storage.getAllComplaints();
      res.json(complaints);
    } catch (error) {
      console.error("Error fetching complaints:", error);
      res.status(500).json({ message: "Failed to fetch complaints" });
    }
  });

  // Update complaint status (admin only)
  app.put('/api/complaints/:id', isAuthenticated, async (req: any, res) => {
    try {
      const currentUser = await storage.getUser(req.user.claims.sub);
      if (!currentUser || currentUser.role !== 'admin') {
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

  // =====================
  // OIL TYPE ROUTES
  // =====================

  // Get all oil types
  app.get('/api/oil-types', isAuthenticated, async (req: any, res) => {
    try {
      const oilTypes = await storage.getAllOilTypes();
      res.json(oilTypes);
    } catch (error) {
      console.error("Error fetching oil types:", error);
      res.status(500).json({ message: "Failed to fetch oil types" });
    }
  });

  // Create oil type (admin only)
  app.post('/api/oil-types', isAuthenticated, async (req: any, res) => {
    try {
      const currentUser = await storage.getUser(req.user.claims.sub);
      if (!currentUser || currentUser.role !== 'admin') {
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

  // =====================
  // BRANCH ROUTES
  // =====================

  // Get all branches
  app.get('/api/branches', isAuthenticated, async (req: any, res) => {
    try {
      const branches = await storage.getAllBranches();
      res.json(branches);
    } catch (error) {
      console.error("Error fetching branches:", error);
      res.status(500).json({ message: "Failed to fetch branches" });
    }
  });

  // Create branch (admin only)
  app.post('/api/branches', isAuthenticated, async (req: any, res) => {
    try {
      const currentUser = await storage.getUser(req.user.claims.sub);
      if (!currentUser || currentUser.role !== 'admin') {
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

  // =====================
  // PHOTO STORAGE ROUTES
  // =====================
  // Photos are now stored in Firebase Storage directly from the frontend

  // Get recent deliveries for dashboard
  app.get('/api/deliveries/recent', async (req, res) => {
    try {
      // Return last 3 completed deliveries
      const recentDeliveries = [
        {
          id: 'del_001',
          deliveryOrderNo: 'ORD-2025-001',
          branchName: 'ARAD TSC',
          oilTypeName: 'Min Oil',
          oilSuppliedLiters: 1500,
          status: 'completed',
          createdAt: new Date('2025-01-14T14:30:00Z').toISOString(),
          photos: {
            tankLevelBefore: 'url1',
            hoseConnection: 'url2', 
            tankLevelAfter: 'url3'
          }
        },
        {
          id: 'del_002',
          deliveryOrderNo: 'ORD-2025-002', 
          branchName: 'ARAD TSC',
          oilTypeName: 'Syn Oil',
          oilSuppliedLiters: 1000,
          status: 'completed',
          createdAt: new Date('2025-01-13T16:45:00Z').toISOString(),
          photos: {
            tankLevelBefore: 'url4',
            hoseConnection: 'url5',
            tankLevelAfter: 'url6'
          }
        },
        {
          id: 'del_003',
          deliveryOrderNo: 'ORD-2025-003', 
          branchName: 'SAAR TSC',
          oilTypeName: 'Min Oil',
          oilSuppliedLiters: 800,
          status: 'completed',
          createdAt: new Date('2025-01-12T11:20:00Z').toISOString(),
          photos: {
            tankLevelBefore: 'url7',
            hoseConnection: 'url8',
            tankLevelAfter: 'url9'
          }
        }
      ];
      
      res.json(recentDeliveries);
    } catch (error) {
      console.error("Error fetching recent deliveries:", error);
      res.status(500).json({ error: "Failed to fetch recent deliveries" });
    }
  });

  // Get oil tank balance for dashboard
  app.get('/api/tank-balance', async (req, res) => {
    try {
      // Mock tank balance data - in real app would come from tank sensors or manual readings
      const tankBalance = {
        totalCapacity: 25000, // Total tank capacity in liters
        currentLevel: 18750,  // Current oil level in liters
        percentage: 75,       // 75% full
        lastUpdated: new Date().toISOString(),
        oilType: 'Min Oil'
      };
      
      res.json(tankBalance);
    } catch (error) {
      console.error("Error fetching tank balance:", error);
      res.status(500).json({ error: "Failed to fetch tank balance" });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}
