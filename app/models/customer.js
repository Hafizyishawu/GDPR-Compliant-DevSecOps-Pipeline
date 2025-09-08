const mongoose = require('mongoose');

const customerSchema = new mongoose.Schema({
    // basic customer data
    customerId: { type: String, required: true, unique: true },

    // PII data (Personal Identifiable Information)
    personalData: {
        firstName: { type: String, required: true },
        lastName: { type: String, required: true },
        email: { type: String, required: true, unique: true },
        phone: String,
        dateOfBirth: Date,
        address: {
            street: String,
            city: String,
            postcode: String,
            country: { type: String, default: 'UK' }
        }
    },

    // GDPR compliance fields
    gdprConsent: {
        marketing: { type: Boolean, default: false },
        analytics: { type: Boolean, default: false },
        consentDate: { type: Date, default: Date.now },
        consentVersion: { type: String, default: '1.0' }
    },

    // Data lifecycle management
    dataRetention: {
        createdAt: { type: Date, default: Date.now },
        retentionPeriod: { type: Number, default: 2555 },
        scheduledDeletion: Date
    },

    // Audit trail
    auditLog: [{
        actions: String, //'created', 'updated', 'accessed, exported'
        timestamp: { type: Date, default: Date.now },
        user: String,
        changes: Object
    }]
});

// GDPR Article 17 - Right to Erasure
customerSchema.methods.requestErasure = function() {
    // Don't actually delete - mark for deletion to maintain audit trail
    this.personalData = {
        firstName: '[ERASED]',
        lastName: '[ERASED]',
        email: '[ERASED]',
        phone: '[ERASED]',
    };
    this.auditLog.push({
        actions: 'erasure_requested',
        timestamp: new Date(),
        user: 'customer_request'

    });
    return this.save();
};

module.exports = mongoose.model('Customer', customerSchema);
