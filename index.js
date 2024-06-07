const express = require("express");
const cors = require("cors");
const app = express();
const jwt = require("jsonwebtoken");
require("dotenv").config();
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const port = process.env.PORT || 5000;

// middleware
app.use(express.json());
app.use(cors());

const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.5e8b5ac.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

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

    const userCollections = client.db("MedDiagnostic").collection("users");
    const allTestCollections = client.db("MedDiagnostic").collection("allTest");
    const reviewCollections = client.db("MedDiagnostic").collection("reviews");
    const blogCollections = client.db("MedDiagnostic").collection("blogs");
    const allBannerCollections = client
      .db("MedDiagnostic")
      .collection("allBanner");
    const bookedTestCollections = client
      .db("MedDiagnostic")
      .collection("bookedTest");

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

    // user related api
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
      //   verifyAdmin,
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
      }
    );
    // get all user
    app.get("/users", verifyToken, verifyAdmin, async (req, res) => {
      console.log(req.headers);
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

    //  patch user
    app.patch("/users/admin/:id", async (req, res) => {
      const id = req.params.id;
      const filter = { _id: new ObjectId(id) };
      const updatedDoc = {
        $set: {
          role: "admin",
        },
      };
      const result = await userCollections.updateOne(filter, updatedDoc);
      res.send(result);
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
        { returnOriginal: "false" }
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
    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
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

app.listen(port, () => {
  console.log(`project is running at ${port}`);
});
