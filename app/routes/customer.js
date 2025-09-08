const express = require('express');
const customer = require('../models/customer');
const router = express.Router();

//Article 6 - Lawful basis for processing
router.post('/customers', async (req, res) => {
 try {
    // validate consent was given
    if (!req.body.gdprConsent || !req.body.gdprConsent.marketing) {
        return res.status(400).json({
            error: 'GDPR consent required for data processing'
        });
    }

    const customer = new customer(req.body);
    await customer.save();

    //Log the creation for audit purposes
    customer.auditLog.push({
        actions: 'created',
        user: req.user ||'app_user'
    });

    res.status(201).json({customerid: customer.customerId });
} catch (error) {
    res.status(400).json({ error: error.message });
}
});

// Article 15 - Right to Access
router.get('/customers/:id/data-export', async (req, res) => {
    try {
      const customer = await customer.findOne(req.params.id);
      if (!customer) {
        return res.status(404).json({ error: 'Customer not found' });
      }

      //log the access for audit purposes
      customer.auditLog.push({
        actions: 'data_exported',
        user: req.user ||'app_user'
    });
    await customer.save();

    // Return all data we hold about them
    res.json({
        exportedData: new Date(),
        customerId: customer.customerId,
        personalData: customer.personalData,
        consents: customer.gdprConsent,
        auditLog: customer.auditLog
    });
} catch (error) {
    res.status(500).json({ error: error.message });
}
});

// Article 17 - Right to Erasure
router.delete('/customers/:id', async (req, res) => {
    try {
       const customer = await customer.findOne({customerId: req.params.id});
       if (!customer) {
        return res.status(404).json({ error: 'Customer not found' });
       }


       await customer.requestErasure();
       res.json({ message: 'Data erasure completed' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;
