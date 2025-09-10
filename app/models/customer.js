const mongoose = require('mongoose');

// GDPR-compliant customer schema
const customerSchema = new mongoose.Schema({
  customerId: {
    type: String,
    required: true,
    unique: true,
    index: true
  },

  // Article 4 - Personal data definition
  personalData: {
    firstName: { type: String, required: true, maxlength: 50 },
    lastName: { type: String, required: true, maxlength: 50 },
    email: {
      type: String,
      required: true,
      lowercase: true,
      validate: {
        validator: function(email) {
          return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
        },
        message: 'Invalid email format'
      }
    },
    phone: {
      type: String,
      validate: {
        validator: function(phone) {
          return !phone || /^\+44[0-9]{10}$/.test(phone);
        },
        message: 'Phone must be UK format (+44xxxxxxxxxx)'
      }
    },
    dateOfBirth: Date,
    address: {
      street: String,
      city: String,
      postcode: {
        type: String,
        validate: {
          validator: function(postcode) {
            return !postcode || /^[A-Z]{1,2}[0-9R][0-9A-Z]?\s?[0-9][A-Z]{2}$/.test(postcode);
          },
          message: 'Invalid UK postcode format'
        }
      },
      country: { type: String, default: 'UK' }
    }
  },

  // Article 6 - Lawful basis tracking
  gdprConsent: {
    marketing: { type: Boolean, required: true },
    analytics: { type: Boolean, default: false },
    consentDate: { type: Date, default: Date.now },
    consentVersion: { type: String, default: '1.0' },
    ipAddress: String,
    userAgent: String
  },

  // Article 5 - Storage limitation
  dataRetention: {
    createdAt: { type: Date, default: Date.now },
    retentionPeriod: { type: Number, default: 2555 }, // 7 years in days
    scheduledDeletion: Date,
    isErased: { type: Boolean, default: false }
  },

  // Article 30 - Records of processing activities
  auditLog: [{
    action: {
      type: String,
      enum: ['created', 'updated', 'accessed', 'exported', 'erasure_requested', 'rectification'],
      required: true
    },
    timestamp: { type: Date, default: Date.now },
    user: String,
    ipAddress: String,
    userAgent: String,
    changes: Object,
    purpose: String,
    gdprArticle: String
  }]
}, {
  timestamps: true
});

// Article 17 - Right to erasure implementation
customerSchema.methods.requestErasure = function() {
  // Pseudonymization instead of hard deletion for audit compliance
  this.personalData = {
    firstName: '[ERASED]',
    lastName: '[ERASED]',
    email: '[ERASED]',
    phone: '[ERASED]',
    dateOfBirth: null,
    address: {
      street: '[ERASED]',
      city: '[ERASED]',
      postcode: '[ERASED]',
      country: 'UK'
    }
  };

  this.dataRetention.isErased = true;
  this.auditLog.push({
    action: 'erasure_requested',
    timestamp: new Date(),
    user: 'data_subject_request',
    gdprArticle: 'Article 17 - Right to erasure'
  });

  return this.save();
};

// Index for efficient querying
customerSchema.index({ 'personalData.email': 1 });
customerSchema.index({ 'dataRetention.scheduledDeletion': 1 });

module.exports = mongoose.model('Customer', customerSchema);
