// ==========================================
// NALLA BROKERS - BACKEND SERVER
// ==========================================

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

// ==========================================
// INITIALIZE EXPRESS
// ==========================================
const app = express();
const PORT = process.env.PORT || 5000;

// ==========================================
// DATABASE CONNECTION
// ==========================================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// Test database connection
pool.connect((err, client, release) => {
  if (err) {
    console.error('❌ Database connection failed:', err.stack);
  } else {
    console.log('✅ Connected to Supabase PostgreSQL');
    release();
  }
});

// ==========================================
// MIDDLEWARE
// ==========================================
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ==========================================
// JWT SECRET (Change this in production!)
// ==========================================
const JWT_SECRET = process.env.JWT_SECRET || 'nallabrokers_super_secret_key_2026';

// ==========================================
// HELPERS
// ==========================================
const generateToken = (user) => {
  return jwt.sign(
    { 
      id: user.id, 
      email: user.email, 
      role: user.role 
    },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
};

const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token.' });
  }
};

// ==========================================
// API ROUTES
// ==========================================

// ---------- HEALTH CHECK ----------
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'Nalla Brokers API is running!',
    timestamp: new Date().toISOString()
  });
});

// ---------- AUTH: REGISTER ----------
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, phone, password, full_name, role, mediator_license, company_name } = req.body;
    
    // Validate required fields
    if (!email || !phone || !password || !full_name) {
      return res.status(400).json({ error: 'Email, phone, password, and full name are required' });
    }
    
    // Check if user exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE email = $1 OR phone = $2',
      [email, phone]
    );
    
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'User with this email or phone already exists' });
    }
    
    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    // Insert user
    const result = await pool.query(
      `INSERT INTO users (email, phone, password_hash, full_name, role, mediator_license, company_name, is_verified)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING id, email, phone, full_name, role, mediator_license, company_name, is_verified, created_at`,
      [email, phone, hashedPassword, full_name, role || 'buyer', mediator_license, company_name, false]
    );
    
    const user = result.rows[0];
    const token = generateToken(user);
    
    res.status(201).json({
      message: 'User registered successfully',
      user,
      token
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// ---------- AUTH: LOGIN ----------
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    
    // Find user
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );
    
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const user = result.rows[0];
    
    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Generate token
    const token = generateToken(user);
    
    // Remove password hash from response
    delete user.password_hash;
    
    res.json({
      message: 'Login successful',
      user,
      token
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// ---------- AUTH: GET CURRENT USER ----------
app.get('/api/auth/me', verifyToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, email, phone, full_name, role, is_verified, mediator_license, company_name, created_at FROM users WHERE id = $1',
      [req.user.id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- PROPERTIES: GET ALL (with filters) ----------
app.get('/api/properties', async (req, res) => {
  try {
    const { district, city, property_type, min_price, max_price, status, limit = 50, offset = 0 } = req.query;
    
    let query = `
      SELECT 
        p.*,
        u.full_name AS mediator_name,
        u.phone AS mediator_phone,
        u.company_name AS mediator_company,
        (SELECT pi.image_url FROM property_images pi WHERE pi.property_id = p.id AND pi.is_main = TRUE LIMIT 1) AS main_image
      FROM properties p
      LEFT JOIN users u ON p.mediator_id = u.id
      WHERE p.status = 'available'
    `;
    
    const params = [];
    let paramCount = 1;
    
    if (district) {
      query += ` AND p.district = $${paramCount}`;
      params.push(district);
      paramCount++;
    }
    
    if (city) {
      query += ` AND p.city = $${paramCount}`;
      params.push(city);
      paramCount++;
    }
    
    if (property_type) {
      query += ` AND p.property_type = $${paramCount}`;
      params.push(property_type);
      paramCount++;
    }
    
    if (min_price) {
      query += ` AND p.selling_price >= $${paramCount}`;
      params.push(min_price);
      paramCount++;
    }
    
    if (max_price) {
      query += ` AND p.selling_price <= $${paramCount}`;
      params.push(max_price);
      paramCount++;
    }
    
    query += ` ORDER BY p.created_at DESC LIMIT $${paramCount} OFFSET $${paramCount + 1}`;
    params.push(parseInt(limit), parseInt(offset));
    
    const result = await pool.query(query, params);
    
    // Get total count
    let countQuery = `SELECT COUNT(*) FROM properties p WHERE p.status = 'available'`;
    if (district) countQuery += ` AND p.district = '${district}'`;
    if (city) countQuery += ` AND p.city = '${city}'`;
    if (property_type) countQuery += ` AND p.property_type = '${property_type}'`;
    
    const countResult = await pool.query(countQuery);
    
    res.json({
      properties: result.rows,
      total: parseInt(countResult.rows[0].count),
      limit: parseInt(limit),
      offset: parseInt(offset)
    });
  } catch (error) {
    console.error('Get properties error:', error);
    res.status(500).json({ error: 'Server error fetching properties' });
  }
});

// ---------- PROPERTIES: GET FOR MAP ----------
app.get('/api/properties/map-pins', async (req, res) => {
  try {
    const { district, city, village } = req.query;
    
    let query = `
      SELECT 
        id,
        property_id,
        title,
        selling_price,
        property_type,
        latitude,
        longitude,
        district,
        city,
        village,
        (SELECT pi.image_url FROM property_images pi WHERE pi.property_id = properties.id AND pi.is_main = TRUE LIMIT 1) AS thumbnail,
        (SELECT COUNT(*) FROM inquiries WHERE property_id = properties.id) AS inquiry_count
      FROM properties
      WHERE status = 'available'
    `;
    
    const params = [];
    let paramCount = 1;
    
    if (district) {
      query += ` AND district = $${paramCount}`;
      params.push(district);
      paramCount++;
    }
    
    if (city) {
      query += ` AND city = $${paramCount}`;
      params.push(city);
      paramCount++;
    }
    
    if (village) {
      query += ` AND village = $${paramCount}`;
      params.push(village);
      paramCount++;
    }
    
    const result = await pool.query(query, params);
    
    res.json(result.rows);
  } catch (error) {
    console.error('Get map pins error:', error);
    res.status(500).json({ error: 'Server error fetching map data' });
  }
});

// ---------- PROPERTIES: GET BY ID ----------
app.get('/api/properties/:propertyId', async (req, res) => {
  try {
    const { propertyId } = req.params;
    
    const result = await pool.query(
      `SELECT 
        p.*,
        u.full_name AS mediator_name,
        u.phone AS mediator_phone,
        u.email AS mediator_email,
        u.company_name AS mediator_company,
        u.mediator_license AS mediator_license,
        (SELECT JSON_AGG(json_build_object('id', pi.id, 'image_url', pi.image_url, 'is_main', pi.is_main, 'order_index', pi.order_index)) 
         FROM property_images pi WHERE pi.property_id = p.id) AS images,
        (SELECT JSON_AGG(json_build_object('id', pd.id, 'document_name', pd.document_name, 'document_url', pd.document_url, 'document_type', pd.document_type)) 
         FROM property_documents pd WHERE pd.property_id = p.id) AS documents
      FROM properties p
      LEFT JOIN users u ON p.mediator_id = u.id
      WHERE p.property_id = $1`,
      [propertyId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Property not found' });
    }
    
    // Increment views
    await pool.query(
      'UPDATE properties SET views_count = views_count + 1 WHERE property_id = $1',
      [propertyId]
    );
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Get property detail error:', error);
    res.status(500).json({ error: 'Server error fetching property details' });
  }
});

// ---------- PROPERTIES: CREATE (Mediator only) ----------
app.post('/api/properties', verifyToken, async (req, res) => {
  try {
    // Check if user is mediator or admin
    if (req.user.role !== 'mediator' && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Only mediators can post properties' });
    }
    
    const {
      title,
      description,
      property_type,
      selling_price,
      commission_percent,
      address,
      district,
      city,
      village,
      state,
      pincode,
      latitude,
      longitude,
      land_area,
      built_up_area,
      bedrooms,
      bathrooms,
      floor_number,
      total_floors,
      facing,
      north_neighbor,
      south_neighbor,
      east_neighbor,
      west_neighbor
    } = req.body;
    
    // Validate required fields
    if (!title || !description || !property_type || !selling_price || !address || !district || !city || !latitude || !longitude) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    // Create PostGIS point
    const location = `POINT(${longitude} ${latitude})`;
    
    const result = await pool.query(
      `INSERT INTO properties (
        mediator_id, title, description, property_type, selling_price, 
        commission_percent, address, district, city, village, state, pincode,
        latitude, longitude, location,
        land_area, built_up_area, bedrooms, bathrooms,
        floor_number, total_floors, facing,
        north_neighbor, south_neighbor, east_neighbor, west_neighbor
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, ST_SetSRID(ST_MakePoint($15, $16), 4326), $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27)
      RETURNING id, property_id, title, description, selling_price, district, city, latitude, longitude`,
      [
        req.user.id, title, description, property_type, selling_price,
        commission_percent || 1.0, address, district, city, village, state || 'Tamil Nadu', pincode,
        latitude, longitude, longitude, latitude,
        land_area, built_up_area, bedrooms || 0, bathrooms || 0,
        floor_number, total_floors, facing,
        north_neighbor, south_neighbor, east_neighbor, west_neighbor
      ]
    );
    
    res.status(201).json({
      message: 'Property posted successfully!',
      property: result.rows[0]
    });
  } catch (error) {
    console.error('Create property error:', error);
    res.status(500).json({ error: 'Server error creating property' });
  }
});

// ---------- PROPERTIES: UPDATE ----------
app.put('/api/properties/:propertyId', verifyToken, async (req, res) => {
  try {
    const { propertyId } = req.params;
    
    // Check if property exists and user owns it
    const checkResult = await pool.query(
      'SELECT mediator_id FROM properties WHERE property_id = $1',
      [propertyId]
    );
    
    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: 'Property not found' });
    }
    
    if (checkResult.rows[0].mediator_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'You do not own this property' });
    }
    
    // Build update query dynamically
    const updates = [];
    const params = [];
    let paramCount = 1;
    
    const allowedFields = [
      'title', 'description', 'property_type', 'selling_price',
      'address', 'district', 'city', 'village', 'state', 'pincode',
      'latitude', 'longitude', 'land_area', 'built_up_area',
      'bedrooms', 'bathrooms', 'floor_number', 'total_floors',
      'facing', 'north_neighbor', 'south_neighbor', 'east_neighbor', 'west_neighbor',
      'status'
    ];
    
    for (const field of allowedFields) {
      if (req.body[field] !== undefined) {
        updates.push(`${field} = $${paramCount}`);
        params.push(req.body[field]);
        paramCount++;
      }
    }
    
    if (updates.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }
    
    // If latitude/longitude updated, update location too
    if (req.body.latitude !== undefined && req.body.longitude !== undefined) {
      updates.push(`location = ST_SetSRID(ST_MakePoint($${paramCount}, $${paramCount + 1}), 4326)`);
      params.push(req.body.longitude, req.body.latitude);
      paramCount += 2;
    }
    
    params.push(propertyId);
    
    const query = `
      UPDATE properties 
      SET ${updates.join(', ')}, updated_at = CURRENT_TIMESTAMP
      WHERE property_id = $${paramCount}
      RETURNING *
    `;
    
    const result = await pool.query(query, params);
    
    res.json({
      message: 'Property updated successfully',
      property: result.rows[0]
    });
  } catch (error) {
    console.error('Update property error:', error);
    res.status(500).json({ error: 'Server error updating property' });
  }
});

// ---------- PROPERTIES: DELETE ----------
app.delete('/api/properties/:propertyId', verifyToken, async (req, res) => {
  try {
    const { propertyId } = req.params;
    
    // Check if property exists and user owns it
    const checkResult = await pool.query(
      'SELECT mediator_id FROM properties WHERE property_id = $1',
      [propertyId]
    );
    
    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: 'Property not found' });
    }
    
    if (checkResult.rows[0].mediator_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'You do not own this property' });
    }
    
    await pool.query(
      'DELETE FROM properties WHERE property_id = $1',
      [propertyId]
    );
    
    res.json({ message: 'Property deleted successfully' });
  } catch (error) {
    console.error('Delete property error:', error);
    res.status(500).json({ error: 'Server error deleting property' });
  }
});

// ---------- INQUIRIES: CREATE ----------
app.post('/api/inquiries', async (req, res) => {
  try {
    const { property_id, buyer_name, buyer_email, buyer_phone, message, inquiry_type } = req.body;
    
    if (!property_id || !buyer_name || !buyer_phone) {
      return res.status(400).json({ error: 'Property ID, name, and phone are required' });
    }
    
    const result = await pool.query(
      `INSERT INTO inquiries (property_id, buyer_id, buyer_name, buyer_email, buyer_phone, message, inquiry_type)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [
        property_id,
        null, // buyer_id will be linked when user logs in
        buyer_name,
        buyer_email,
        buyer_phone,
        message,
        inquiry_type || 'general'
      ]
    );
    
    // Increment inquiry count on property
    await pool.query(
      'UPDATE properties SET inquiries_count = inquiries_count + 1 WHERE id = $1',
      [property_id]
    );
    
    res.status(201).json({
      message: 'Inquiry sent successfully! The mediator will contact you soon.',
      inquiry: result.rows[0]
    });
  } catch (error) {
    console.error('Create inquiry error:', error);
    res.status(500).json({ error: 'Server error creating inquiry' });
  }
});

// ---------- INQUIRIES: GET BY MEDIATOR ----------
app.get('/api/inquiries/mediator', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'mediator' && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Only mediators can view inquiries' });
    }
    
    const result = await pool.query(
      `SELECT 
        i.*,
        p.property_id,
        p.title AS property_title,
        p.selling_price,
        p.district,
        p.city
      FROM inquiries i
      LEFT JOIN properties p ON i.property_id = p.id
      WHERE p.mediator_id = $1
      ORDER BY i.created_at DESC`,
      [req.user.id]
    );
    
    res.json(result.rows);
  } catch (error) {
    console.error('Get mediator inquiries error:', error);
    res.status(500).json({ error: 'Server error fetching inquiries' });
  }
});

// ---------- DISTRICTS: GET ALL ----------
app.get('/api/districts', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT district_name, district_code FROM tamil_nadu_districts ORDER BY district_name'
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Get districts error:', error);
    res.status(500).json({ error: 'Server error fetching districts' });
  }
});

// ---------- DASHBOARD: ADMIN STATS ----------
app.get('/api/dashboard/admin', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const statsResult = await pool.query(`
      SELECT 
        (SELECT COUNT(*) FROM users) AS total_users,
        (SELECT COUNT(*) FROM users WHERE role = 'mediator') AS total_mediators,
        (SELECT COUNT(*) FROM users WHERE role = 'buyer') AS total_buyers,
        (SELECT COUNT(*) FROM properties) AS total_properties,
        (SELECT COUNT(*) FROM properties WHERE status = 'available') AS available_properties,
        (SELECT COUNT(*) FROM properties WHERE status = 'pending') AS pending_properties,
        (SELECT COUNT(*) FROM properties WHERE status = 'sold') AS sold_properties,
        (SELECT COALESCE(SUM(selling_price), 0) FROM properties WHERE status = 'sold') AS total_sales_value,
        (SELECT COUNT(*) FROM inquiries) AS total_inquiries,
        (SELECT COUNT(*) FROM inquiries WHERE status = 'new') AS new_inquiries,
        (SELECT COUNT(*) FROM chat_messages) AS total_messages
    `);
    
    // Recent activity
    const recentResult = await pool.query(`
      SELECT 
        'property' AS type,
        property_id AS identifier,
        title AS name,
        created_at,
        'new property listed' AS description
      FROM properties
      ORDER BY created_at DESC
      LIMIT 5
    `);
    
    res.json({
      stats: statsResult.rows[0],
      recent_activity: recentResult.rows
    });
  } catch (error) {
    console.error('Admin dashboard error:', error);
    res.status(500).json({ error: 'Server error fetching dashboard data' });
  }
});

// ---------- DASHBOARD: MEDIATOR STATS ----------
app.get('/api/dashboard/mediator', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'mediator') {
      return res.status(403).json({ error: 'Mediator access required' });
    }
    
    const statsResult = await pool.query(`
      SELECT 
        (SELECT COUNT(*) FROM properties WHERE mediator_id = $1) AS total_listings,
        (SELECT COUNT(*) FROM properties WHERE mediator_id = $1 AND status = 'available') AS active_listings,
        (SELECT COUNT(*) FROM properties WHERE mediator_id = $1 AND status = 'pending') AS pending_listings,
        (SELECT COUNT(*) FROM properties WHERE mediator_id = $1 AND status = 'sold') AS sold_listings,
        (SELECT COALESCE(SUM(views_count), 0) FROM properties WHERE mediator_id = $1) AS total_views,
        (SELECT COALESCE(SUM(inquiries_count), 0) FROM properties WHERE mediator_id = $1) AS total_inquiries
    `, [req.user.id]);
    
    // Recent inquiries for this mediator
    const inquiriesResult = await pool.query(`
      SELECT 
        i.*,
        p.property_id,
        p.title AS property_title
      FROM inquiries i
      LEFT JOIN properties p ON i.property_id = p.id
      WHERE p.mediator_id = $1
      ORDER BY i.created_at DESC
      LIMIT 10
    `, [req.user.id]);
    
    res.json({
      stats: statsResult.rows[0],
      recent_inquiries: inquiriesResult.rows
    });
  } catch (error) {
    console.error('Mediator dashboard error:', error);
    res.status(500).json({ error: 'Server error fetching dashboard data' });
  }
});

// ==========================================
// START SERVER
// ==========================================
app.listen(PORT, () => {
  console.log(`🚀 Nalla Brokers Backend running on port ${PORT}`);
  console.log(`📍 Health check: http://localhost:${PORT}/api/health`);
});

module.exports = app;