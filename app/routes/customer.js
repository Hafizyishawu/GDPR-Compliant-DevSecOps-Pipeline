const express = require('express');
const Customer = require('../models/Customer');
const Joi = require('joi');
const winston = require('winston');
const router = express.Router();

// GDPR-compliant validation schema
const customerSchema = Joi.object({
  personalData: Joi.object({
    firstName: Joi.string().min(1).max(50).required(),
    lastName: Joi.string().min(1).max(50).required(),
    email: Joi.string().email().required(),
    phone: Joi.string().pattern(/^\+44[0-9]{10}$/).optional(),
    dateOfBirth: Joi.date().max('now').optional(),
    address: Joi.object({
      street: Joi.string().max(100).optional(),
      city: Joi.string().max(50).optional(),
      postcode: Joi.string().pattern(/^[A-Z]{1,2}[0-9R][0-9A-Z]?\s?[0-9][A-Z]{2}$/).optional(),
      country: Joi.string().default('UK')
    }).optional()
  }).required(),
  gdprConsent: Joi.object({
    marketing: Joi.boolean().required(),
    analytics: Joi.boolean().default(false),
    consentVersion: Joi.string().default('1.0')
  }).required()
});

// Article 6 - Lawful basis for processing
router.post('/customers', async (req, res) => {
  try {
    // Validate GDPR consent BEFORE processing
    if (!req.body.gdprConsent || !req.body.gdprConsent.marketing) {
      return res.status(400).json({
        error: 'GDPR consent required for data processing',
        gdprArticle: 'Article 6 - Lawfulness of processing'
      });
    }

    // Validate input data
    const { error, value } = customerSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        error: 'Validation failed',
        details: error.details[0].message
      });
    }

    // Create customer with audit trail
    const customer = new Customer({
      customerId: `CUST_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      ...value,
      dataRetention: {
        createdAt: new Date(),
        retentionPeriod: 2555, // 7 years
        scheduledDeletion: new Date(Date.now() + (2555 * 24 * 60 * 60 * 1000))
      }
    });

    // Article 30 - Records of processing activities
    customer.auditLog.push({
      action: 'created',
      timestamp: new Date(),
      user: req.headers['x-user-id'] || 'api_user',
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    await customer.save();

    // Return only necessary data (data minimization)
    res.status(201).json({
      customerId: customer.customerId,
      message: 'Customer created successfully',
      gdprCompliant: true
    });

  } catch (error) {
    winston.error('Customer creation error:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: 'Failed to create customer'
    });
  }
});

// Article 15 - Right of access (Data Subject Access Request)
router.get('/customers/:id/data-export', async (req, res) => {
  try {
    const customer = await Customer.findOne({ customerId: req.params.id });

    if (!customer) {
      return res.status(404).json({
        error: 'Customer not found',
        gdprNote: 'No personal data found for this identifier'
      });
    }

    // Article 30 - Log the access
    customer.auditLog.push({
      action: 'data_exported',
      timestamp: new Date(),
      user: req.headers['x-user-id'] || 'api_user',
      ipAddress: req.ip,
      purpose: 'Data subject access request'
    });
    await customer.save();

    // Provide comprehensive data export
    const dataExport = {
      exportMetadata: {
        exportDate: new Date().toISOString(),
        gdprArticle: 'Article 15 - Right of access',
        dataController: 'Your Company Name',
        retentionPeriod: `${customer.dataRetention.retentionPeriod} days`
      },
      personalData: customer.personalData,
      consentHistory: {
        current: customer.gdprConsent,
        consentDate: customer.gdprConsent.consentDate
      },
      dataProcessingHistory: customer.auditLog,
      dataRetentionInfo: customer.dataRetention
    };

    res.json(dataExport);

  } catch (error) {
    winston.error('Data export error:', error);
    res.status(500).json({ error: 'Failed to export data' });
  }
});

// Article 17 - Right to erasure ("Right to be Forgotten")
router.delete('/customers/:id', async (req, res) => {
  try {
    const customer = await Customer.findOne({ customerId: req.params.id });

    if (!customer) {
      return res.status(404).json({ error: 'Customer not found' });
    }

    // Implement erasure (pseudonymization to maintain audit trail)
    await customer.requestErasure();

    res.json({
      message: 'Data erasure completed',
      gdprArticle: 'Article 17 - Right to erasure',
      timestamp: new Date().toISOString(),
      note: 'Personal data has been erased while maintaining audit trail for compliance'
    });

  } catch (error) {
    winston.error('Data erasure error:', error);
    res.status(500).json({ error: 'Failed to erase data' });
  }
});

// Article 16 - Right to rectification
router.put('/customers/:id', async (req, res) => {
  try {
    const customer = await Customer.findOne({ customerId: req.params.id });

    if (!customer) {
      return res.status(404).json({ error: 'Customer not found' });
    }

    // Validate update data
    const updateSchema = Joi.object({
      personalData: Joi.object({
        firstName: Joi.string().min(1).max(50).optional(),
        lastName: Joi.string().min(1).max(50).optional(),
        email: Joi.string().email().optional(),
        phone: Joi.string().pattern(/^\+44[0-9]{10}$/).optional(),
        address: Joi.object({
          street: Joi.string().max(100).optional(),
          city: Joi.string().max(50).optional(),
          postcode: Joi.string().pattern(/^[A-Z]{1,2}[0-9R][0-9A-Z]?\s?[0-9][A-Z]{2}$/).optional()
        }).optional()
      }).optional()
    });

    const { error, value } = updateSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        error: 'Validation failed',
        details: error.details[0].message
      });
    }

    // Record what changed for audit trail
    const changes = {};
    if (value.personalData) {
      Object.keys(value.personalData).forEach(key => {
        if (customer.personalData[key] !== value.personalData[key]) {
          changes[key] = {
            from: customer.personalData[key],
            to: value.personalData[key]
          };
        }
      });
    }

    // Update customer data
    if (value.personalData) {
      customer.personalData = { ...customer.personalData, ...value.personalData };
    }

    // Article 30 - Audit log the changes
    customer.auditLog.push({
      action: 'rectification',
      timestamp: new Date(),
      user: req.headers['x-user-id'] || 'api_user',
      changes: changes,
      gdprArticle: 'Article 16 - Right to rectification'
    });

    await customer.save();

    res.json({
      message: 'Customer data updated successfully',
      customerId: customer.customerId,
      changesApplied: Object.keys(changes)
    });

  } catch (error) {
    winston.error('Customer update error:', error);
    res.status(500).json({ error: 'Failed to update customer' });
  }
});

module.exports = router;
