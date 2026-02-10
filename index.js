const express = require("express");
const cors = require("cors");
const app = express();
const jwt = require("jsonwebtoken");
require("dotenv").config();
const bcrypt = require("bcryptjs");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const port = process.env.PORT || 5000;
const multer = require("multer");
const path = require("path");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

// -------------------------
// Multer storage configuration
// -------------------------
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, path.join(__dirname, "uploads")); // folder to save uploaded files
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname);
    const name = file.fieldname + "-" + Date.now() + ext;
    cb(null, name);
  },
});

const upload = multer({ storage });

// middleware
app.use(express.json());
app.use(
  cors({
    origin: [
      "http://localhost:3000",
      "https://tutor-media-ehpl.vercel.app",
      "https://www.tutormediabd.com",
    ],
  }),
);

const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

// console.log("DB_USER:", process.env.DB_USER);
// console.log("DB_PASS:", process.env.DB_PASS);

const uri = `mongodb+srv://${encodeURIComponent(process.env.DB_USER)}:${encodeURIComponent(process.env.DB_PASS)}@cluster0.5e8b5ac.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();

    const jobCollections = client.db("tutorHub").collection("allJobs");
    const tutorCollections = client.db("tutorHub").collection("allTutors");
    const blogsCollections = client.db("tutorHub").collection("allBlogs");
    const countersCollection = client.db("tutorHub").collection("counters");
    const applicationsCollection = client
      .db("tutorHub")
      .collection("applications");
    const userCollections = client.db("tutorHub").collection("users");
    const paymentCollections = client.db("tutorHub").collection("payments");

    // jwt related api
    app.post("/jwt", async (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "1h",
      });
      res.send({ token });
    });

    //   middlewares
    const verifyToken = (req, res, next) => {
      if (!req.headers.authorization) {
        return res.status(401).send({ message: "forbidden" });
      }
      const token = req.headers.authorization.split(" ")[1];
      jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) {
          return res.status(401).send({ message: "forbidden" });
        }
        req.decoded = decoded;
        next();
      });
    };
    const verifyAdmin = async (req, res, next) => {
      const email = req.decoded.email;
      const query = { email: email };
      const user = await userCollections.findOne(query);
      const isAdmin = user?.role === "admin";
      if (!isAdmin) {
        return res.status(401).send({ message: "forbidden" });
      }
      next();
    };

    // forgot password
    app.post("/forgot-password", async (req, res) => {
      const { email } = req.body;

      const tutor = await tutorCollections.findOne({ email });
      if (!tutor) {
        return res.status(404).send({ message: "Tutor not found" });
      }

      const token = crypto.randomBytes(32).toString("hex");
      const expires = Date.now() + 1000 * 60 * 15; // 15 minutes

      await tutorCollections.updateOne(
        { email },
        {
          $set: {
            resetToken: token,
            resetTokenExpires: expires,
          },
        },
      );

      const resetLink = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;

      const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASSWORD,
        },
      });

      await transporter.sendMail({
        from: `"Tutor Media" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: "Password Reset",
        html: `
      <p>You requested a password reset.</p>
      <p>Click below to reset your password:</p>
      <a href="${resetLink}">${resetLink}</a>
      <p>This link expires in 15 minutes.</p>
    `,
      });

      res.send({ success: true, message: "Reset link sent" });
    });

    // reset password
    app.post("/reset-password", async (req, res) => {
      const { token, password } = req.body;

      const tutor = await tutorCollections.findOne({
        resetToken: token,
        resetTokenExpires: { $gt: Date.now() },
      });

      if (!tutor) {
        return res.status(400).send({ message: "Invalid or expired token" });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      await tutorCollections.updateOne(
        { _id: tutor._id },
        {
          $set: { password: hashedPassword },
          $unset: { resetToken: "", resetTokenExpires: "" },
        },
      );

      res.send({ success: true, message: "Password updated successfully" });
    });

    // login (supports both normal users and tutors)
    app.post("/login", async (req, res) => {
      const { email, password } = req.body;
      const query = { email: email };
      // Then try tutors
      const tutor = await tutorCollections.findOne(query);
      if (!tutor) {
        return res.status(401).send({ message: "Invalid credentials" });
      }
      // Compare password — try bcrypt first, then fallback to plain-text comparison for legacy accounts
      let match = false;
      try {
        if (tutor.password) {
          match = await bcrypt.compare(password || "", tutor.password);
        }
      } catch (err) {
        // if bcrypt throws for malformed hash, ignore and fallback to string comparison
        match = false;
      }
      // Fallback for legacy plain-text passwords stored in DB
      if (!match) {
        match = (password || "") === (tutor.password || "");
      }

      if (!match) {
        return res.status(401).send({ message: "Invalid credentials" });
      }

      // Create JWT and return tutor (without password) and redirect URL for frontend
      const token = jwt.sign(
        { email: tutor.email, role: "tutor" },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: "1h" },
      );
      const { password: pwd, ...safeTutor } = tutor;

      const redirectUrl = process.env.FRONTEND_URL
        ? `${process.env.FRONTEND_URL}/profile`
        : "http://localhost:3000/profile";

      res.send({
        success: true,
        role: "tutor",
        tutor: safeTutor,
        token,
        redirect: redirectUrl,
      });
    });

    // user related api
    // get all jobs
    app.get("/allJobs", async (req, res) => {
      const result = await jobCollections.find().toArray();
      res.send(result);
    });
    // get all jobs deleted
    app.get("/allJobs/deleted", async (req, res) => {
      const result = await jobCollections
        .find({
          $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
        })
        .toArray();
      res.send(result);
    });

    // get specific job
    app.get("/allJobs/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await jobCollections.findOne(query);
      res.send(result);
    });

    // post a job
    app.post("/allJobs", async (req, res) => {
      try {
        const job = req.body;

        // Generate unique numeric ID for the job
        const counterResult = await countersCollection.findOneAndUpdate(
          { _id: "jobId" },
          { $inc: { seq: 1 } },
          { upsert: true, returnDocument: "after" },
        );

        // Fallback if findOneAndUpdate returns null
        let newId;
        if (counterResult && counterResult.value && counterResult.value.seq) {
          newId = counterResult.value.seq;
        } else {
          const counterDoc = await countersCollection.findOne({ _id: "jobId" });
          if (!counterDoc) {
            return res
              .status(500)
              .send({ message: "Failed to generate unique ID" });
          }
          newId = counterDoc.seq;
        }

        job.id = newId;
        job.createdAt = new Date();
        // job.applications = job.applications || [];

        const result = await jobCollections.insertOne(job);
        res.status(201).send(result);
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: error.message });
      }
    });

    // get all tutors
    app.get("/allTutors", async (req, res) => {
      const result = await tutorCollections.find().toArray();
      res.send(result);
    });

    // get all tutors
    app.get("/allTutors/deleted", async (req, res) => {
      const result = await tutorCollections
        .find({
          $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
        })
        .toArray();
      res.send(result);
    });

    // get specific tutor

    // app.get("/allTutors/:id", async (req, res) => {
    //   const { id } = req.params;
    //   // Try matching common possibilities: string id, numeric id, documentId, or _id
    //   const orClauses = [{ id }, { id: Number(id) }, { documentId: id }];
    //   try {
    //     if (ObjectId.isValid(id)) orClauses.push({ _id: new ObjectId(id) });
    //   } catch (_) {}

    //   const tutor = await tutorCollections.findOne({ $or: orClauses });

    //   if (!tutor) {
    //     return res.status(404).json({ message: "Tutor not found" });
    //   }
    //   return res.json(tutor);
    // });

    app.get("/allTutors/:id", async (req, res) => {
      const { id } = req.params;

      // Build possible search queries
      const orClauses = [{ id }, { id: Number(id) }, { documentId: id }];

      if (ObjectId.isValid(id)) {
        orClauses.push({ _id: new ObjectId(id) });
      }

      try {
        const tutor = await tutorCollections.findOne({ $or: orClauses });

        if (!tutor) return res.status(404).json({ message: "Tutor not found" });

        return res.json(tutor); // will include email, etc.
      } catch (error) {
        console.error(error);
        return res.status(500).json({ message: "Server error" });
      }
    });

    // become a tutor
    app.post("/allTutors", async (req, res) => {
      try {
        const tutor = req.body; // ✅ get data from request

        // Generate unique numeric ID
        const counterResult = await countersCollection.findOneAndUpdate(
          { _id: "tutorId" },
          { $inc: { seq: 1 } },
          { upsert: true, returnDocument: "after" }, // correct for MongoDB driver v4+
        );

        // Fallback if findOneAndUpdate returns null
        let newId;
        if (counterResult && counterResult.value && counterResult.value.seq) {
          newId = counterResult.value.seq;
        } else {
          const counterDoc = await countersCollection.findOne({
            _id: "tutorId",
          });
          if (!counterDoc) {
            return res
              .status(500)
              .send({ message: "Failed to generate unique ID" });
          }
          newId = counterDoc.seq;
        }

        tutor.id = newId;
        tutor.createdAt = new Date();

        // Check email uniqueness
        const exists = await tutorCollections.findOne({ email: tutor.email });
        if (exists) {
          return res
            .status(400)
            .send({ message: "This email is already registered" });
        }

        // Require password and hash it
        if (!tutor.password) {
          return res.status(400).send({ message: "Password is required" });
        }
        const hashedPassword = await bcrypt.hash(tutor.password, 10);
        tutor.password = hashedPassword;
        tutor.role = "tutor";

        // Insert tutor (don't return password in response)
        const result = await tutorCollections.insertOne(tutor);
        const { password, ...safeTutor } = tutor;
        res.status(201).send({
          success: true,
          insertedId: result.insertedId,
          tutor: safeTutor,
        });
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: error.message });
      }
    });

    // patch tutor flags (admin only)
    app.patch("/allTutors/isApproved/:id", async (req, res) => {
      try {
        const { id } = req.params;
        const orClauses = [{ id }, { id: Number(id) }, { documentId: id }];
        if (ObjectId.isValid(id)) orClauses.push({ _id: new ObjectId(id) });
        const tutor = await tutorCollections.findOne({ $or: orClauses });
        if (!tutor) return res.status(404).json({ message: "Tutor not found" });

        const filter = tutor._id ? { _id: tutor._id } : { id: tutor.id };
        const newApprovedStatus = !tutor.isApproved;
        const updatedDoc = {
          $set: { isApproved: newApprovedStatus, approvedAt: new Date() },
        };
        const result = await tutorCollections.updateOne(filter, updatedDoc);
        res.send(result);
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: error.message });
      }
    });

    app.patch("/allTutors/isPremium/:id", async (req, res) => {
      try {
        const { id } = req.params;
        const orClauses = [{ id }, { id: Number(id) }, { documentId: id }];
        if (ObjectId.isValid(id)) orClauses.push({ _id: new ObjectId(id) });
        const tutor = await tutorCollections.findOne({ $or: orClauses });
        if (!tutor) return res.status(404).json({ message: "Tutor not found" });

        const filter = tutor._id ? { _id: tutor._id } : { id: tutor.id };
        const newPremiumStatus = !tutor.isPremium;
        const updatedDoc = {
          $set: { isPremium: newPremiumStatus, premiumAt: new Date() },
        };
        const result = await tutorCollections.updateOne(filter, updatedDoc);
        res.send(result);
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: error.message });
      }
    });

    app.patch("/allTutors/isVerified/:id", async (req, res) => {
      try {
        const { id } = req.params;
        const orClauses = [{ id }, { id: Number(id) }, { documentId: id }];
        if (ObjectId.isValid(id)) orClauses.push({ _id: new ObjectId(id) });
        const tutor = await tutorCollections.findOne({ $or: orClauses });
        if (!tutor) return res.status(404).json({ message: "Tutor not found" });

        const filter = tutor._id ? { _id: tutor._id } : { id: tutor.id };
        const newVerifiedStatus = !tutor.isVerified;
        const updatedDoc = {
          $set: { isVerified: newVerifiedStatus, verifiedAt: new Date() },
        };
        const result = await tutorCollections.updateOne(filter, updatedDoc);
        res.send(result);
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: error.message });
      }
    });

    // Update tutor profile
    app.put("/allTutors/:id", async (req, res) => {
      try {
        const { id } = req.params;
        const profileData = req.body;

        // Build possible search queries
        const orClauses = [{ id }, { id: Number(id) }, { documentId: id }];
        if (ObjectId.isValid(id)) orClauses.push({ _id: new ObjectId(id) });

        const tutor = await tutorCollections.findOne({ $or: orClauses });
        if (!tutor) return res.status(404).json({ message: "Tutor not found" });

        const filter = tutor._id ? { _id: tutor._id } : { id: tutor.id };
        const updatedDoc = {
          $set: { ...profileData, updatedAt: new Date() },
        };

        const result = await tutorCollections.updateOne(filter, updatedDoc);

        if (result.matchedCount === 0) {
          return res.status(404).json({ message: "Tutor not found" });
        }

        res.json({
          message: "Tutor profile updated successfully",
          modifiedCount: result.modifiedCount,
        });
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: error.message });
      }
    });

    // Update tutor with partial data
    app.patch(
      "/allTutors/update/:id",
      upload.any(), // MUST for FormData
      async (req, res) => {
        try {
          const { id } = req.params;
          const updateData = {};

          // Parse normal fields from FormData
          for (const key in req.body) {
            try {
              updateData[key] = JSON.parse(req.body[key]);
            } catch {
              updateData[key] = req.body[key];
            }
          }

          // Handle uploaded files
          if (req.files) {
            req.files.forEach((file) => {
              // Save the file path in documentsInfo
              updateData.documentsInfo = updateData.documentsInfo || {};
              updateData.documentsInfo[file.fieldname] =
                `/uploads/${file.filename}`;
            });
          }

          // Ensure documentsInfo fields are preserved if no new file uploaded
          const docFields = [
            "nidFront",
            "nidBack",
            "universityId",
            "sscCertificate",
            "hscCertificate",
          ];
          updateData.documentsInfo = updateData.documentsInfo || {};
          docFields.forEach((key) => {
            // If not in uploaded files, preserve string from FormData
            if (!updateData.documentsInfo[key] && req.body[key]) {
              updateData.documentsInfo[key] = req.body[key];
            }
          });

          // Find tutor
          const orClauses = [{ id }, { id: Number(id) }];
          if (ObjectId.isValid(id)) orClauses.push({ _id: new ObjectId(id) });
          const tutor = await tutorCollections.findOne({ $or: orClauses });
          if (!tutor)
            return res.status(404).json({ message: "Tutor not found" });

          // Update DB
          await tutorCollections.updateOne(
            { _id: tutor._id },
            { $set: { ...updateData, updatedAt: new Date() } },
          );

          res.json({ message: "Tutor updated successfully" });
        } catch (error) {
          console.error(error);
          res.status(500).json({ message: error.message });
        }
      },
    );

    // patch job approval (admin only)

    app.patch("/allJobs/isApproved/:id", async (req, res) => {
      try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
          return res.status(400).json({ message: "Invalid ID" });
        }

        const filter = { _id: new ObjectId(id) };
        const update = {
          $set: {
            isApproved: req.body.isApproved,
            approvedAt: new Date(),
          },
        };

        const result = await jobCollections.updateOne(filter, update);

        res.json(result);
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // soft delete tutor (admin only)
    app.patch("/allTutors/delete/:id", async (req, res) => {
      try {
        const { id } = req.params;

        const orClauses = [{ id }, { id: Number(id) }, { documentId: id }];
        if (ObjectId.isValid(id)) orClauses.push({ _id: new ObjectId(id) });

        const tutor = await tutorCollections.findOne({ $or: orClauses });
        if (!tutor) {
          return res.status(404).json({ message: "Tutor not found" });
        }

        const filter = tutor._id ? { _id: tutor._id } : { id: tutor.id };

        const updateDoc = {
          $set: {
            isDeleted: true,
            deletedAt: new Date(),
          },
        };

        const result = await tutorCollections.updateOne(filter, updateDoc);
        res.send(result);
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: error.message });
      }
    });

    // restore deleted tutor
    app.patch("/allTutors/restore/:id", async (req, res) => {
      try {
        const { id } = req.params;

        const orClauses = [{ id }, { id: Number(id) }, { documentId: id }];
        if (ObjectId.isValid(id)) orClauses.push({ _id: new ObjectId(id) });

        const tutor = await tutorCollections.findOne({ $or: orClauses });
        if (!tutor) {
          return res.status(404).json({ message: "Tutor not found" });
        }

        const filter = tutor._id ? { _id: tutor._id } : { id: tutor.id };

        const updateDoc = {
          $set: {
            isDeleted: false,
          },
          $unset: {
            deletedAt: "",
          },
        };

        const result = await tutorCollections.updateOne(filter, updateDoc);
        res.send(result);
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: error.message });
      }
    });

    // soft delete tuition job (admin only)
    app.patch("/allJobs/delete/:id", async (req, res) => {
      try {
        const { id } = req.params;

        const orClauses = [{ id }, { id: Number(id) }, { documentId: id }];
        if (ObjectId.isValid(id)) orClauses.push({ _id: new ObjectId(id) });

        const job = await jobCollections.findOne({ $or: orClauses });
        if (!job) {
          return res.status(404).json({ message: "Job not found" });
        }

        const filter = job._id ? { _id: job._id } : { id: job.id };

        const updateDoc = {
          $set: {
            isDeleted: true,
            deletedAt: new Date(),
          },
        };

        const result = await jobCollections.updateOne(filter, updateDoc);

        res.json({
          success: true,
          modifiedCount: result.modifiedCount,
        });
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: error.message });
      }
    });

    // restore deleted tuition job
    app.patch("/allJobs/restore/:id", async (req, res) => {
      try {
        const { id } = req.params;

        const orClauses = [{ id }, { id: Number(id) }, { documentId: id }];
        if (ObjectId.isValid(id)) orClauses.push({ _id: new ObjectId(id) });

        const job = await jobCollections.findOne({ $or: orClauses });
        if (!job) {
          return res.status(404).json({ message: "Job not found" });
        }

        const filter = job._id ? { _id: job._id } : { id: job.id };

        const result = await jobCollections.updateOne(filter, {
          $set: {
            isDeleted: false,
            deletedAt: null,
          },
        });

        res.json({
          success: true,
          modifiedCount: result.modifiedCount,
        });
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: error.message });
      }
    });

    // update tuition job
    app.patch("/allJobs/update/:id", async (req, res) => {
      try {
        const { id } = req.params;
        const updateData = req.body; // 👈 take everything

        if (!updateData || Object.keys(updateData).length === 0) {
          return res
            .status(400)
            .json({ message: "No fields provided to update" });
        }

        const orClauses = [{ id }, { id: Number(id) }, { documentId: id }];
        if (ObjectId.isValid(id)) orClauses.push({ _id: new ObjectId(id) });

        const job = await jobCollections.findOne({ $or: orClauses });
        if (!job) return res.status(404).json({ message: "Job not found" });

        const filter = job._id ? { _id: job._id } : { id: job.id };

        const result = await jobCollections.updateOne(filter, {
          $set: updateData, // 🔥 update all sent fields
        });

        res.json({
          success: true,
          modifiedCount: result.modifiedCount,
          updatedFields: updateData,
        });
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: error.message });
      }
    });

    // blog related api
    // get all blogs
    app.get("/allBlogs", async (req, res) => {
      const result = await blogsCollections.find().toArray();
      res.send(result);
    });
    // get specific blog
    app.get("/allBlogs/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await blogCollections.findOne(query);
      res.send(result);
    });

    // get all applications with job and tutor details
    app.get("/applications", async (req, res) => {
      try {
        const result = await applicationsCollection
          .aggregate([
            {
              $match: {
                $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
              },
            },
            {
              $lookup: {
                from: "allJobs",
                localField: "tuitionJobId",
                foreignField: "_id",
                as: "job",
              },
            },
            {
              $unwind: {
                path: "$job",
                preserveNullAndEmptyArrays: true,
              },
            },
            {
              $lookup: {
                from: "allTutors",
                localField: "tutorId",
                foreignField: "_id",
                as: "tutor",
              },
            },
            {
              $unwind: {
                path: "$tutor",
                preserveNullAndEmptyArrays: true,
              },
            },
          ])
          .toArray();
        res.send(result);
      } catch (error) {
        console.error("Application fetch error:", error);
        res.status(500).json({ message: "Server error", error: error.message });
      }
    });

    // post a appliation
    app.post("/applications", async (req, res) => {
      try {
        const { rate, schedule, proposal, tutorId, tuitionJobId } = req.body;
        console.log(req.body);

        if (!tutorId || !tuitionJobId) {
          return res.status(400).json({
            message: "Tutor ID and Job ID are required",
          });
        }

        const applicationsCollection = client
          .db("tutorHub")
          .collection("applications");

        // Validate tutor & job - tutorId can be numeric id or ObjectId string
        const tutor = await tutorCollections.findOne(
          ObjectId.isValid(tutorId)
            ? { _id: new ObjectId(tutorId) }
            : { id: Number(tutorId) },
        );

        const job = await jobCollections.findOne({
          _id: new ObjectId(tuitionJobId),
        });

        if (!tutor || !job) {
          return res.status(404).json({
            message: "Tutor or Job not found",
          });
        }

        // Create application - store the tutor's actual _id
        const application = {
          rate,
          schedule,
          proposal,
          tutorId: tutor._id, // Store the tutor's _id directly
          tuitionJobId: new ObjectId(tuitionJobId),
          createdAt: new Date(),
        };

        const result = await applicationsCollection.insertOne(application);

        // Push application into job (one job → many applications)
        await jobCollections.updateOne(
          { _id: new ObjectId(tuitionJobId) },
          { $push: { applications: result.insertedId } },
        );

        res.status(201).json({
          success: true,
          data: {
            _id: result.insertedId,
            ...application,
          },
        });
      } catch (error) {
        console.error("Application create error:", error);
        res.status(500).json({ message: "Server error" });
      }
    });

    app.patch("/applications/:id", async (req, res) => {
      try {
        const { isDeleted } = req.body;
        const result = await applicationsCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: { isDeleted } },
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({ message: "Application not found" });
        }

        res.json({ message: "Application updated successfully" });
      } catch (error) {
        console.error("Update error:", error);
        res.status(500).json({ message: "Server error" });
      }
    });

    //post user
    app.post("/users", async (req, res) => {
      const user = req.body;
      const query = { email: user.email };
      const existingUser = await userCollections.findOne(query);
      if (existingUser) {
        return res.send({ message: "user already exists", insertedId: null });
      }
      const result = await userCollections.insertOne(user);
      res.send(result);
    });

    // get exact user
    app.get(
      "/users/admin/:email",
      verifyToken,
      // verifyAdmin,
      async (req, res) => {
        const email = req.params.email;
        if (email !== req.decoded.email) {
          return res.status(403).send({ message: "access forbidden" });
        }
        const query = { email: email };
        const user = await userCollections.findOne(query);
        let admin = false;
        if (user) {
          admin = user?.role === "admin";
        }
        res.send({ admin });
      },
    );

    // get all user
    app.get("/users", verifyToken, verifyAdmin, async (req, res) => {
      // console.log(req.headers);
      const result = await userCollections.find().toArray();
      res.send(result);
    });

    // get specific user
    app.get("/users/:email", async (req, res) => {
      const email = req.params.email;
      const query = { email: email };
      const result = await userCollections.findOne(query);
      res.send(result);
    });

    //  patch user (assign admin) — only one admin allowed
    app.patch("/users/admin/:id", verifyToken, async (req, res) => {
      try {
        const id = req.params.id;

        // Check existing admin
        const existingAdmin = await userCollections.findOne({ role: "admin" });

        // If an admin already exists, only that admin can assign admin and we must ensure we don't create a second admin
        if (existingAdmin) {
          if (req.decoded?.email !== existingAdmin.email) {
            return res
              .status(403)
              .send({ message: "Only current admin can assign admin role" });
          }
          if (existingAdmin._id.toString() !== id) {
            return res.status(400).send({ message: "Only one admin allowed" });
          }
        }

        const filter = { _id: new ObjectId(id) };
        const updatedDoc = {
          $set: {
            role: "admin",
          },
        };
        const result = await userCollections.updateOne(filter, updatedDoc);
        res.send(result);
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: error.message });
      }
    });

    //  patch user 2
    app.patch("/users/status/:id", async (req, res) => {
      const id = req.params.id;
      const filter = { _id: new ObjectId(id) };
      const updatedDoc = {
        $set: {
          status: "blocked",
        },
      };
      const result = await userCollections.updateOne(filter, updatedDoc);
      res.send(result);
    });

    // update user
    app.put("/users/:email", async (req, res) => {
      const user = req.body;
      const email = req.params.email;
      const filter = { email: email };
      const updatedDoc = {
        $set: {
          name: user.name,
          email: user.email,
          image: user.image,
          blood: user.blood,
          district: user.district,
          upazilla: user.upazilla,
        },
      };
      const result = await userCollections.updateOne(filter, updatedDoc);
      res.send(result);
    });
    // Test related api

    // post a test
    app.post("/allTest", verifyToken, verifyAdmin, async (req, res) => {
      const test = req.body;
      const result = await allTestCollections.insertOne(test);
      res.send(result);
    });

    //delete a test
    app.delete("/allTest/:id", verifyToken, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await allTestCollections.deleteOne(query);
      res.send(result);
    });

    // get all test
    app.get("/allTest", async (req, res) => {
      const page = parseInt(req.query.page);
      const size = parseInt(req.query.size);
      const result = await allTestCollections.find().toArray();
      res.send(result);
    });

    // get single test
    app.get("/allTest/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await allTestCollections.findOne(query);
      res.send(result);
    });

    // update a test
    app.patch("/allTest/:id", verifyToken, verifyAdmin, async (req, res) => {
      const test = req.body;
      const id = req.params.id;
      const filter = { _id: new ObjectId(id) };
      const updatedDoc = {
        $set: {
          title: test.title,
          image: test.image,
          price: test.price,
          date: test.date,
          short_description: test.short_description,
          slots: test.slots,
        },
      };
      const result = await allTestCollections.updateOne(filter, updatedDoc);
      res.send(result);
    });

    // booked test related api
    // get all booked test
    app.get("/bookedTest", async (req, res) => {
      const result = await bookedTestCollections.find().toArray();
      res.send(result);
    });
    // get test by email
    app.get("/special/bookedTest", async (req, res) => {
      const email = req.query.email;
      const query = { email: email };
      const result = await bookedTestCollections.find(query).toArray();
      res.send(result);
    });
    // get test by email
    app.get("/bookedTest/:email", async (req, res) => {
      const email = req.params.email;
      const query = { email: email };
      const result = await bookedTestCollections.find(query).toArray();
      res.send(result);
    });
    // get test by id
    app.get("/bookedTest/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await bookedTestCollections.find(query).toArray();
      res.send(result);
    });
    //special get test by id
    app.get("/res/bookedTest/:id", async (req, res) => {
      const id = req.params.id;
      const query = { testId: id };
      const result = await bookedTestCollections.find(query).toArray();
      res.send(result);
    });
    // delete booked test
    app.delete("/bookedTest/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await bookedTestCollections.deleteOne(query);
      res.send(result);
    });
    // post booked test
    app.post("/bookedTest", async (req, res) => {
      const bookedTest = req.body;
      const result = await bookedTestCollections.insertOne(bookedTest);
      res.send(result);
    });
    // patch booked test
    app.patch("/bookedTest/status/:id", async (req, res) => {
      const id = req.params.id;
      const filter = { _id: new ObjectId(id) };
      const updatedDoc = {
        $set: {
          report_status: "Delivered",
        },
      };
      const result = await bookedTestCollections.updateOne(filter, updatedDoc);
      res.send(result);
    });

    // banner related api
    app.get("/allBanner", async (req, res) => {
      const result = await allBannerCollections.find().toArray();
      res.send(result);
    });
    // post a banner
    app.post("/allBanner", async (req, res) => {
      const banner = req.body;
      const result = await allBannerCollections.insertOne(banner);
      res.send(result);
    });
    // delete a banner
    app.delete("/allBanner/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await allBannerCollections.deleteOne(query);
      res.send(result);
    });
    //  patch banner
    app.patch("/allBanner/status/:id", async (req, res) => {
      const id = req.params.id;
      const filter = {};
      const updatedDoc = {
        $set: {
          isActive: "false",
        },
      };
      await allBannerCollections.updateMany(filter, updatedDoc);
      const result = await allBannerCollections.findOneAndUpdate(
        { _id: new ObjectId(id) },
        { $set: { isActive: "true" } },
        { returnOriginal: "false" },
      );
      res.send(result);
    });
    // review related api
    app.get("/reviews", async (req, res) => {
      const result = await reviewCollections.find().toArray();
      res.send(result);
    });
    // blog related api
    app.get("/blogs", async (req, res) => {
      const result = await blogCollections.find().toArray();
      res.send(result);
    });
    // verified post a test
    app.post("/verified", verifyToken, verifyAdmin, async (req, res) => {
      const test = req.body;
      const result = await verifiedTestCollections.insertOne(test);
      res.send(result);
    });
    app.get("/special/verified", async (req, res) => {
      const email = req.query.email;
      const query = { email: email };
      const result = await verifiedTestCollections.find(query).toArray();
      res.send(result);
    });
    // payment intent
    app.post("/create-payment-intent", async (req, res) => {
      const { price } = req.body;
      const amount = parseInt(price * 100);
      const paymentIntent = await stripe.paymentIntents.create({
        amount: amount,
        currency: "usd",
        payment_method_types: ["card"],
      });
      res.send({
        clientSecret: paymentIntent.client_secret,
      });
    });

    // manual payment routes for bkash and other payment methods

    // app.post("/manual-bkash-payment", verifyToken, async (req, res) => {
    //   const paymentData = req.body;
    //   const payment = {
    //     ...paymentData,
    //     number: paymentData.sender,
    //     transactionId: paymentData.trxId,
    //     createdAt: new Date(),
    //     status: "pending",
    //     userEmail: req.decoded.email,
    //   };
    //   const result = await paymentCollections.insertOne(payment);
    //   res.send(result);
    // });

    // post manual payment
    app.post("/manual-bkash-payment", verifyToken, async (req, res) => {
      try {
        const { sender, trxId, plan, amount, tutorId, method } = req.body;

        if (!sender || !trxId || !tutorId) {
          return res.status(400).send({
            message: "Sender, Transaction ID and Tutor ID are required",
          });
        }

        // Duplicate trx check
        const exists = await paymentCollections.findOne({ trxId });
        if (exists) {
          return res.status(409).send({
            message: "This transaction ID has already been used",
          });
        }

        const payment = {
          tutorId: Number(tutorId), // ✅ force number
          plan,
          amount,
          sender,
          trxId,
          method: method || "bkash",
          number: sender,
          transactionId: trxId,
          createdAt: new Date(),
          status: "pending",
          userEmail: req.decoded.email,
        };

        const result = await paymentCollections.insertOne(payment);
        res.status(201).send(result);
      } catch (error) {
        console.error("bKash payment error:", error);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    // get user's payments
    app.get("/manual-bkash-payment", verifyToken, async (req, res) => {
      const email = req.decoded.email;
      const query = { userEmail: email };
      const result = await paymentCollections.find(query).toArray();
      res.send(result);
    });

    // get all payments
    app.get("/all-payments", async (req, res) => {
      const result = await paymentCollections.find().toArray();
      res.send(result);
    });

    // get payments by email (user's own payments)
    app.get("/my-payments", verifyToken, async (req, res) => {
      const email = req.decoded.email;
      const query = { userEmail: email };
      const result = await paymentCollections.find(query).toArray();
      res.send(result);
    });

    // stats chart api
    app.get("/admin-stats", async (req, res) => {
      const users = await userCollections.estimatedDocumentCount();
      const tests = await allTestCollections.estimatedDocumentCount();
      const bookedTests = await bookedTestCollections.estimatedDocumentCount();
      const deliveredTests =
        await verifiedTestCollections.estimatedDocumentCount();
      res.send({
        users,
        tests,
        bookedTests,
        deliveredTests,
      });
    });
    // aggregate
    app.get("/booked-stats", async (req, res) => {
      const result = await bookedTestCollections.aggregate([]).toArray();
      res.send(result);
    });
    // Send a ping to confirm a successful connection
    // await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!",
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("project is running");
});

// Export for Vercel serverless
module.exports = app;

// Local development only
if (process.env.NODE_ENV !== "production") {
  app.listen(port, "0.0.0.0", () => {
    console.log(`project is running at ${port}`);
  });
}
