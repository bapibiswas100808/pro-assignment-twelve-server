const express = require("express");
const cors = require("cors");
const app = express();
require("dotenv").config();
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
    const bookedTestCollections = client
      .db("MedDiagnostic")
      .collection("bookedTest");
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
    // get all user
    app.get("/users", async (req, res) => {
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
    // get all test
    app.get("/allTest", async (req, res) => {
      const page = parseInt(req.query.page);
      const size = parseInt(req.query.size);
      const result = await allTestCollections
        .find()
        .skip(page * size)
        .limit(size)
        .toArray();
      res.send(result);
    });
    // get single test
    app.get("/allTest/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await allTestCollections.findOne(query);
      res.send(result);
    });

    // booked test related api
    // get all booked test
    // app.get("/bookedTest", async (req, res) => {
    //   const result = await bookedTestCollections.find().toArray();
    //   res.send(result);
    // });
    // get test by email
    app.get("/bookedTest", async (req, res) => {
      const email = req.query.email;
      const query = { email: email };
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
