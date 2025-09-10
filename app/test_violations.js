// This contains intentional GDPR violations for testing purposes

const customerEmail = "john.doe@example.com"; // should trigger hardcoded PII rule
console.log("Customer phone:", "+447123456789"); // should trigger PII in logs rule

const customerSchema = new mongoose.Schema({
    email: String // should trigger unencrypted field rule
});

// Missing consent check - should trigger compliance rule
router.post("/test-customers", async (req, res) => {
    const customer = new Customer(req.body);
    await customer.save(); // No consent check
});
