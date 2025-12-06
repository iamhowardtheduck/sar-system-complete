const express = require('express');
const { Client } = require('@elastic/elasticsearch');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const { PDFDocument, PDFForm, PDFTextField, PDFCheckBox } = require('pdf-lib');
const { create } = require('xmlbuilder2');

const app = express();
const PORT = process.env.PORT || 3000;

// Enhanced proxy trust configuration for workshop environment
// Following express-rate-limit security recommendations
// See: https://express-rate-limit.mintlify.app/reference/error-codes#err-erl-permissive-trust-proxy

// Option 1: Trust specific number of proxies (recommended)
app.set('trust proxy', 1); // Trust the first proxy (most common for workshops)

// Option 2: Trust specific IP ranges (more secure)
// Uncomment and use this if Option 1 doesn't work:
// app.set('trust proxy', ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']);

// Option 3: Custom trust function (most secure)
// Uncomment and use this for maximum control:
/*
app.set('trust proxy', (ip) => {
  // Trust localhost
  if (ip === '127.0.0.1' || ip === '::1') return true;
  
  // Trust private networks (common in containerized environments)
  if (ip.startsWith('10.') || 
      ip.startsWith('172.16.') || ip.startsWith('172.17.') || // Docker default
      ip.startsWith('192.168.')) return true;
      
  // Trust Kubernetes service networks
  if (ip.startsWith('10.96.') || ip.startsWith('10.244.')) return true;
  
  return false;
});
*/

// Elasticsearch configuration - Workshop Environment Defaults
const elasticsearchConfig = {
  node: process.env.ELASTICSEARCH_URL || 'http://kubernetes-vm:30920',
  auth: {
    username: process.env.ELASTICSEARCH_USERNAME || 'elastic',
    password: process.env.ELASTICSEARCH_PASSWORD || 'elastic'
  },
  tls: {
    rejectUnauthorized: false // Set to true in production with proper certificates
  }
};

const esClient = new Client(elasticsearchConfig);

// Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"]
    }
  }
}));

app.use(compression());
app.use(morgan('combined'));
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting - Following express-rate-limit best practices
// See: https://express-rate-limit.mintlify.app/guides/troubleshooting-proxy-issues
const enableRateLimiting = process.env.DISABLE_RATE_LIMITING !== 'true';

if (enableRateLimiting) {
  const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    limit: 100, // Limit each IP to 100 requests per windowMs (new syntax)
    standardHeaders: 'draft-7', // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
    
    // Skip rate limiting for certain requests
    skip: (req) => {
      // Skip rate limiting for health checks and static assets
      return req.path === '/api/health' || 
             req.path.startsWith('/css') || 
             req.path.startsWith('/js') ||
             req.path.startsWith('/favicon');
    },
    
    // Custom key generator that works with trusted proxies
    keyGenerator: (req) => {
      // With trust proxy properly configured, req.ip should be the real client IP
      return req.ip;
    },
    
    // Enhanced error handler
    handler: (req, res) => {
      console.log(`Rate limit exceeded for IP: ${req.ip}, Path: ${req.path}`);
      res.status(429).json({
        error: 'Too many requests',
        message: 'Rate limit exceeded. Please try again later.',
        retryAfter: Math.round(15 * 60), // 15 minutes in seconds
        ip: req.ip // Include IP for debugging (remove in production)
      });
    },
    
    // Validate that trust proxy is configured correctly
    validate: {
      trustProxy: false, // Let express-rate-limit validate our trust proxy config
      xForwardedForHeader: true // We expect X-Forwarded-For headers
    }
  });
  
  app.use('/api/', limiter);
  console.log('✓ Rate limiting enabled for API endpoints');
  console.log(`✓ Trust proxy setting: ${app.get('trust proxy')}`);
} else {
  console.log('⚠ Rate limiting disabled for workshop environment');
}

// Serve static files
app.use(express.static('public'));

// Set view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Routes
app.get('/', (req, res) => {
  res.render('index', { 
    title: 'SAR Management System'
  });
});

// API endpoint to get SAR data from Elasticsearch with enhanced fuzzy search
app.get('/api/sar-reports', async (req, res) => {
  try {
    const { page = 1, size = 10, search } = req.query;
    const from = (page - 1) * size;

    let query = { match_all: {} };
    
    if (search) {
      // Enhanced fuzzy search with multiple strategies
      query = {
        bool: {
          should: [
            // Fuzzy search on financial institution name
            {
              fuzzy: {
                financial_institution_name: {
                  value: search,
                  fuzziness: "AUTO",
                  prefix_length: 1,
                  max_expansions: 50
                }
              }
            },
            // Fuzzy search on suspect last name
            {
              fuzzy: {
                suspect_last_name: {
                  value: search,
                  fuzziness: "AUTO",
                  prefix_length: 1,
                  max_expansions: 50
                }
              }
            },
            // Fuzzy search on suspect first name
            {
              fuzzy: {
                suspect_first_name: {
                  value: search,
                  fuzziness: "AUTO",
                  prefix_length: 1,
                  max_expansions: 50
                }
              }
            },
            // Fuzzy search on entity name (for companies)
            {
              fuzzy: {
                suspect_entity_name: {
                  value: search,
                  fuzziness: "AUTO",
                  prefix_length: 1,
                  max_expansions: 50
                }
              }
            },
            // Fuzzy search on activity description
            {
              fuzzy: {
                activity_description: {
                  value: search,
                  fuzziness: "AUTO",
                  prefix_length: 2,
                  max_expansions: 50
                }
              }
            },
            // Fuzzy search on account number
            {
              fuzzy: {
                account_number: {
                  value: search,
                  fuzziness: "AUTO",
                  prefix_length: 1,
                  max_expansions: 50
                }
              }
            },
            // Regular match for exact matches (higher score)
            {
              multi_match: {
                query: search,
                fields: [
                  'financial_institution_name^2',
                  'suspect_last_name^2', 
                  'suspect_first_name^2',
                  'suspect_entity_name^2',
                  'activity_description',
                  'account_number'
                ],
                boost: 2
              }
            }
          ],
          minimum_should_match: 1
        }
      };
    }

    const response = await esClient.search({
      index: process.env.ELASTICSEARCH_INDEX || 'sar-reports',
      body: {
        query: query,
        from: from,
        size: parseInt(size),
        sort: [
          { '@timestamp': { order: 'desc' } },
          { 'report_date': { order: 'desc' } }
        ]
      }
    });

    // Handle different Elasticsearch client response structures
    let hits, total;
    
    console.log('Elasticsearch response structure:', {
      hasBody: !!response.body,
      hasHits: !!response.hits,
      bodyKeys: response.body ? Object.keys(response.body) : [],
      responseKeys: Object.keys(response)
    });
    
    if (response.body && response.body.hits) {
      // Older client structure: response.body.hits
      hits = response.body.hits.hits || [];
      total = response.body.hits.total?.value || response.body.hits.total || 0;
    } else if (response.hits) {
      // Newer client structure: response.hits
      hits = response.hits.hits || [];
      total = response.hits.total?.value || response.hits.total || 0;
    } else {
      // Fallback: no hits found
      console.warn('Unexpected Elasticsearch response structure:', response);
      hits = [];
      total = 0;
    }

    const reports = hits.map(hit => ({
      id: hit._id,
      ...hit._source
    }));

    res.json({
      reports,
      total: total,
      page: parseInt(page),
      totalPages: Math.ceil(total / size)
    });

  } catch (error) {
    console.error('Error fetching SAR reports:', error);
    
    // Handle specific authentication errors
    if (error.meta && error.meta.statusCode === 401) {
      return res.status(401).json({ 
        error: 'Authentication failed - check Elasticsearch credentials',
        details: 'The user does not have permission to search the SAR reports index',
        suggestion: 'Verify username/password and user permissions in Elasticsearch'
      });
    }
    
    // Handle index not found errors
    if (error.meta && error.meta.statusCode === 404) {
      return res.status(404).json({ 
        error: 'SAR reports index not found',
        details: 'The sar-reports index does not exist in Elasticsearch',
        suggestion: 'Run load-sample-data.sh to create the index and load sample data'
      });
    }
    
    res.status(500).json({ 
      error: 'Failed to fetch SAR reports',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error',
      suggestion: 'Check Elasticsearch connectivity and credentials'
    });
  }
});

// API endpoint to get a specific SAR report
app.get('/api/sar-reports/:id', async (req, res) => {
  try {
    const response = await esClient.get({
      index: process.env.ELASTICSEARCH_INDEX || 'sar-reports',
      id: req.params.id
    });

    // Handle different Elasticsearch client response structures
    let source, id;
    
    if (response.body && response.body._source) {
      // Older client structure: response.body._source
      source = response.body._source;
      id = response.body._id;
    } else if (response._source) {
      // Newer client structure: response._source
      source = response._source;
      id = response._id;
    } else {
      throw new Error('Unexpected response structure from Elasticsearch');
    }

    res.json({
      id: id,
      ...source
    });

  } catch (error) {
    console.error('Error fetching SAR report:', error);
    if (error.meta && error.meta.statusCode === 404) {
      res.status(404).json({ error: 'SAR report not found' });
    } else {
      res.status(500).json({ 
        error: 'Failed to fetch SAR report',
        details: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }
});

// API endpoint to generate FinCEN Form 8300 XML for a specific SAR report
app.get('/api/sar-reports/:id/fincen8300', async (req, res) => {
  try {
    // Get the SAR report data
    const reportResponse = await esClient.get({
      index: process.env.ELASTICSEARCH_INDEX || 'sar-reports',
      id: req.params.id
    });

    let source, reportId;
    
    if (reportResponse.body && reportResponse.body._source) {
      source = reportResponse.body._source;
      reportId = reportResponse.body._id;
    } else if (reportResponse._source) {
      source = reportResponse._source;
      reportId = reportResponse._id;
    } else {
      throw new Error('Unexpected response structure from Elasticsearch');
    }

    // Generate the FinCEN 8300 XML
    const xmlContent = generateFinCEN8300XML(source, reportId);
    
    // Create filename and file path
    const filename = `FinCEN-8300-${reportId}-${new Date().toISOString().split('T')[0]}.xml`;
    const filePath = path.join(__dirname, filename);
    
    // Save XML to server directory
    fs.writeFileSync(filePath, xmlContent, 'utf8');
    console.log(`✅ XML saved to: ${filePath}`);
    
    // Also send to browser for download
    res.setHeader('Content-Type', 'application/xml');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Length', Buffer.byteLength(xmlContent, 'utf8'));
    
    res.send(xmlContent);

  } catch (error) {
    console.error('Error generating FinCEN 8300 XML:', error);
    if (error.meta && error.meta.statusCode === 404) {
      res.status(404).json({ error: 'SAR report not found' });
    } else {
      res.status(500).json({ 
        error: 'Failed to generate FinCEN 8300 XML',
        details: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
      });
    }
  }
});

// API endpoint to list generated files in the server directory
app.get('/api/generated-files', (req, res) => {
  try {
    const files = fs.readdirSync(__dirname)
      .filter(file => file.match(/^(SAR-Report-|FinCEN-8300-).*(\.pdf|\.xml)$/))
      .map(filename => {
        const filePath = path.join(__dirname, filename);
        const stats = fs.statSync(filePath);
        return {
          filename,
          path: filePath,
          size: stats.size,
          created: stats.birthtime,
          modified: stats.mtime,
          type: filename.endsWith('.pdf') ? 'PDF' : 'XML'
        };
      })
      .sort((a, b) => b.modified - a.modified); // Sort by most recent first

    res.json({
      files,
      count: files.length,
      directory: __dirname
    });

  } catch (error) {
    console.error('Error listing generated files:', error);
    res.status(500).json({ 
      error: 'Failed to list generated files',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// Function to generate FinCEN Form 8300 XML
function generateFinCEN8300XML(reportData, reportId) {
  try {
    // Text cleaning function to prevent XML issues
    const cleanXMLText = (text, maxLength = null) => {
      if (!text) return '';
      
      let cleanText = String(text)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&apos;')
        .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
      
      if (maxLength && cleanText.length > maxLength) {
        cleanText = cleanText.substring(0, maxLength);
      }
      
      return cleanText;
    };

    // Sequential number generator for XML elements
    let seqNum = 1;
    const getSeqNum = () => seqNum++;
    
    // Date formatting for FinCEN
    const formatFinCENDate = (dateString) => {
      if (!dateString) return '';
      try {
        const date = new Date(dateString);
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const day = String(date.getDate()).padStart(2, '0');
        return `${year}${month}${day}`;
      } catch {
        return '';
      }
    };

    // Create XML document
    const doc = create({ version: '1.0', encoding: 'UTF-8' })
      .ele('EFilingBatchXML', {
        'xmlns': 'www.fincen.gov/base',
        'xmlns:xsi': 'http://www.w3.org/2001/XMLSchema-instance',
        'xsi:schemaLocation': 'www.fincen.gov/base https://www.fincen.gov/base'
      })
      .ele('Activity', { 'SeqNum': getSeqNum() })
        .ele('ActivityAssociation', { 'SeqNum': getSeqNum() })
          .ele('CorrectsAmendsPriorReportIndicator').txt('N').up()
          .ele('FinCENDirectBackFileIndicator').txt('N').up()
        .up()
        
        .ele('Party', { 'SeqNum': getSeqNum() })
          .ele('ActivityPartyTypeCode').txt('35').up() // Filing institution
          .ele('PrimaryRegulatorTypeCode').txt('9').up() // Other
          .ele('PartyName', { 'SeqNum': getSeqNum() })
            .ele('PartyNameTypeCode').txt('L').up() // Legal name
            .ele('RawPartyFullName').txt(cleanXMLText(reportData.financial_institution_name || 'Unknown Institution', 150)).up()
          .up()
          .ele('Address', { 'SeqNum': getSeqNum() })
            .ele('RawCityText').txt(cleanXMLText(reportData.financial_institution_city || '', 50)).up()
            .ele('RawCountryCodeText').txt('US').up()
            .ele('RawStateCodeText').txt(cleanXMLText(reportData.financial_institution_state || '', 3)).up()
            .ele('RawStreetAddress1Text').txt(cleanXMLText(reportData.financial_institution_address || '', 100)).up()
            .ele('RawZIPCode').txt(cleanXMLText(reportData.financial_institution_zip || '', 10)).up()
          .up()
          .ele('PartyIdentification', { 'SeqNum': getSeqNum() })
            .ele('PartyIdentificationNumberText').txt(cleanXMLText(reportData.financial_institution_ein || '', 25)).up()
            .ele('PartyIdentificationTypeCode').txt('2').up() // EIN
          .up()
        .up()
        
        .ele('Party', { 'SeqNum': getSeqNum() })
          .ele('ActivityPartyTypeCode').txt('23').up() // Person conducting transaction
          .ele('IndividualBirthDateText').txt(formatFinCENDate(reportData.suspect_date_of_birth)).up()
          .ele('PartyName', { 'SeqNum': getSeqNum() })
            .ele('PartyNameTypeCode').txt('L').up()
            .ele('RawEntityIndividualLastName').txt(cleanXMLText(reportData.suspect_last_name || reportData.suspect_entity_name || '', 150)).up()
            .ele('RawIndividualFirstName').txt(cleanXMLText(reportData.suspect_first_name || '', 35)).up()
          .up()
          .ele('Address', { 'SeqNum': getSeqNum() })
            .ele('RawCityText').txt(cleanXMLText(reportData.suspect_city || '', 50)).up()
            .ele('RawCountryCodeText').txt(cleanXMLText(reportData.suspect_country || 'US', 2)).up()
            .ele('RawStateCodeText').txt(cleanXMLText(reportData.suspect_state || '', 3)).up()
            .ele('RawStreetAddress1Text').txt(cleanXMLText(reportData.suspect_address || '', 100)).up()
            .ele('RawZIPCode').txt(cleanXMLText(reportData.suspect_zip || '', 10)).up()
          .up()
          .ele('PhoneNumber', { 'SeqNum': getSeqNum() })
            .ele('PhoneNumberText').txt(cleanXMLText(reportData.suspect_phone || '', 16)).up()
          .up()
          .ele('PartyIdentification', { 'SeqNum': getSeqNum() })
            .ele('PartyIdentificationNumberText').txt(cleanXMLText(reportData.suspect_ssn_tin || '', 25)).up()
            .ele('PartyIdentificationTypeCode').txt('1').up() // SSN
          .up()
          .ele('PartyOccupationBusiness', { 'SeqNum': getSeqNum() })
            .ele('OccupationBusinessText').txt(cleanXMLText(reportData.suspect_occupation || '', 50)).up()
          .up()
        .up()
        
        .ele('CurrencyTransactionActivity', { 'SeqNum': getSeqNum() })
          .ele('CurrencyTransactionActivityDetail', { 'SeqNum': getSeqNum() })
            .ele('CurrencyTransactionActivityDetailTypeCode').txt('1').up()
            .ele('DetailTransactionAmountText').txt(String(reportData.total_dollar_amount || 0)).up()
            .ele('DetailTransactionDescription').txt(cleanXMLText(reportData.activity_description || 'Suspicious cash transaction')).up()
            .ele('InstrumentProductServiceTypeCode').txt('35').up()
          .up()
          
          .ele('CurrencyTransactionActivity', { 'SeqNum': getSeqNum() })
            .ele('CurrencyTransactionActivityDetailTypeCode').txt('999').up()
            .ele('DetailTransactionAmountText').txt('0').up()
            .ele('DetailTransactionDescription').txt('Related to suspicious activity report').up()
            .ele('InstrumentProductServiceTypeCode').txt('35').up()
          .up()
        .up()
        
        .ele('ActivityNarrativeInformation', { 'SeqNum': getSeqNum() })
          .ele('ActivityNarrativeSequenceNumber').txt('1').up()
          .ele('ActivityNarrativeText').txt(cleanXMLText(
            `This Form 8300 filing is based on suspicious activity identified in SAR report ${reportId}. ` +
            `Transaction details: ${reportData.activity_description || 'Cash transaction above reporting threshold'}. ` +
            `Additional investigation may be warranted.`, 750
          )).up()
        .up()
      .up();

    return doc.end({ prettyPrint: true });
    
  } catch (error) {
    console.error('Error generating FinCEN 8300 XML:', error);
    throw new Error(`Failed to generate FinCEN 8300 XML: ${error.message}`);
  }
}

// API endpoint to generate filled PDF for a specific SAR report
app.get('/api/sar-reports/:id/pdf', async (req, res) => {
  try {
    // Get the SAR report data
    const reportResponse = await esClient.get({
      index: process.env.ELASTICSEARCH_INDEX || 'sar-reports',
      id: req.params.id
    });

    let source, reportId;
    
    if (reportResponse.body && reportResponse.body._source) {
      source = reportResponse.body._source;
      reportId = reportResponse.body._id;
    } else if (reportResponse._source) {
      source = reportResponse._source;
      reportId = reportResponse._id;
    } else {
      throw new Error('Unexpected response structure from Elasticsearch');
    }

    // Generate the filled PDF
    const pdfBytes = await generateFilledSARPdf(source);
    
    // Create filename and file path
    const filename = `SAR-Report-${reportId}-${new Date().toISOString().split('T')[0]}.pdf`;
    const filePath = path.join(__dirname, filename);
    
    // Save PDF to server directory
    fs.writeFileSync(filePath, pdfBytes);
    console.log(`✅ PDF saved to: ${filePath}`);
    
    // Also send to browser for download
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Length', pdfBytes.length);
    
    res.send(Buffer.from(pdfBytes));

  } catch (error) {
    console.error('Error generating SAR PDF:', error);
    if (error.meta && error.meta.statusCode === 404) {
      res.status(404).json({ error: 'SAR report not found' });
    } else {
      res.status(500).json({ 
        error: 'Failed to generate SAR PDF',
        details: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
      });
    }
  }
});

// Function to generate filled SAR PDF
async function generateFilledSARPdf(reportData) {
  try {
    // Try to use template if available, otherwise create summary
    const templatePath = path.join(__dirname, 'sar-template.pdf');
    
    if (fs.existsSync(templatePath)) {
      const existingPdfBytes = fs.readFileSync(templatePath);
      const pdfDoc = await PDFDocument.load(existingPdfBytes, { 
        ignoreEncryption: true,
        updateMetadata: false
      });

      try {
        // Try to get form and fill fields
        const form = pdfDoc.getForm();
        
        if (form) {
          console.log('✓ PDF form found, attempting to fill fields...');
          
          // Field mapping with error handling
          const fieldMappings = [
            { name: '2_Institution_Name', value: reportData.financial_institution_name },
            { name: '3_EIN', value: reportData.financial_institution_ein },
            { name: '4_Address', value: reportData.financial_institution_address },
            { name: '6_City', value: reportData.financial_institution_city },
            { name: '7_State', value: reportData.financial_institution_state },
            { name: '8_ZIP', value: reportData.financial_institution_zip },
            { name: '9_Phone', value: reportData.financial_institution_phone },
            { name: '14_Account_Numbers', value: reportData.account_number },
            { name: '15_Last_Name', value: reportData.suspect_last_name || reportData.suspect_entity_name },
            { name: '16_First_Name', value: reportData.suspect_first_name },
            { name: '18_Address', value: reportData.suspect_address },
            { name: '20_City', value: reportData.suspect_city },
            { name: '21_State', value: reportData.suspect_state },
            { name: '22_ZIP', value: reportData.suspect_zip },
            { name: '24_Phone', value: reportData.suspect_phone },
            { name: '33_Date', value: formatDateForPDF(reportData.suspicious_activity_date) },
            { name: '34_Amount', value: formatCurrencyForPDF(reportData.total_dollar_amount) }
          ];

          fieldMappings.forEach(({ name, value }) => {
            try {
              if (value) {
                const field = form.getField(name);
                if (field instanceof PDFTextField) {
                  field.setText(String(value));
                }
              }
            } catch (fieldError) {
              console.log(`⚠ Could not fill field "${name}": ${fieldError.message}`);
            }
          });

          const pdfBytes = await pdfDoc.save();
          return pdfBytes;
        }
      } catch (formError) {
        console.log('⚠ Could not process PDF form, creating summary instead');
      }
    }
    
    // Fallback: Create data summary
    console.error('Error in generateFilledSARPdf:', error);
    try {
      return await createSARDataSummaryPdf(await PDFDocument.create(), reportData);
    } catch (fallbackError) {
      throw new Error(`Failed to generate PDF: ${fallbackError.message}`);
    }
  } catch (error) {
    console.log('📝 Creating SAR data summary PDF');
    return await createSARDataSummaryPdf(await PDFDocument.create(), reportData);
  }
}

// Function to create PDF with form overlay (when template exists but form filling fails)
async function createPdfWithTextOverlay(pdfDoc, reportData) {
  try {
    const pages = pdfDoc.getPages();
    const firstPage = pages[0];
    const { width, height } = firstPage.getSize();
    const font = await pdfDoc.embedFont('Helvetica');
    
    // Add text overlays at approximate field positions
    // These coordinates would need to be adjusted based on your actual SAR template
    const overlays = [
      { x: 150, y: height - 120, text: reportData.financial_institution_name, size: 10 },
      { x: 150, y: height - 140, text: reportData.financial_institution_ein, size: 10 },
      { x: 150, y: height - 160, text: reportData.financial_institution_address, size: 10 },
      // Add more field positions as needed
    ];

    overlays.forEach(overlay => {
      if (overlay.text) {
        firstPage.drawText(String(overlay.text), {
          x: overlay.x,
          y: overlay.y,
          size: overlay.size,
          font: font,
        });
      }
    });

    const pdfBytes = await pdfDoc.save();
    return pdfBytes;
    
  } catch (error) {
    console.error('Error creating PDF with text overlay:', error);
    // Fallback: create simple data summary
    return await createSARDataSummaryPdf(await PDFDocument.create(), reportData);
  }
}

// Create a clean SAR data summary PDF
async function createSARDataSummaryPdf(pdfDoc, reportData) {
  try {
    const page = pdfDoc.addPage([612, 792]); // Standard letter size
    const { width, height } = page.getSize();
    const font = await pdfDoc.embedFont('Helvetica');
    const boldFont = await pdfDoc.embedFont('Helvetica-Bold');
    
    let yPosition = height - 50;
    const lineHeight = 18;
    const leftMargin = 50;
    const rightMargin = width - 50;
    
    // Header
    page.drawText('SUSPICIOUS ACTIVITY REPORT (SAR)', {
      x: leftMargin,
      y: yPosition,
      size: 18,
      font: boldFont,
    });
    
    page.drawText('DATA SUMMARY', {
      x: leftMargin,
      y: yPosition - 25,
      size: 14,
      font: boldFont,
    });
    
    page.drawText(`Generated: ${new Date().toLocaleDateString()}`, {
      x: rightMargin - 150,
      y: yPosition - 25,
      size: 10,
      font: font,
    });
    
    yPosition -= 60;
    
    // Draw a line
    page.drawLine({
      start: { x: leftMargin, y: yPosition },
      end: { x: rightMargin, y: yPosition },
      thickness: 1,
    });
    yPosition -= 30;
    
    // Helper function for sections
    const addSection = (title, fields) => {
      page.drawText(title, {
        x: leftMargin,
        y: yPosition,
        size: 14,
        font: boldFont,
      });
      yPosition -= 25;
      
      fields.forEach(([label, value, fieldNum]) => {
        if (value && yPosition > 50) {
          const fieldText = fieldNum ? ` (Field ${fieldNum})` : '';
          page.drawText(`${label}${fieldText}:`, {
            x: leftMargin + 10,
            y: yPosition,
            size: 10,
            font: boldFont,
          });
          
          // Clean and truncate long text
          const cleanValue = String(value).substring(0, 60);
          
          page.drawText(cleanValue, {
            x: leftMargin + 150,
            y: yPosition,
            size: 10,
            font: font,
          });
          yPosition -= lineHeight;
        }
      });
      yPosition -= 15;
    };
    
    // Financial Institution Section
    addSection('PART I - FINANCIAL INSTITUTION INFORMATION', [
      ['Name', reportData.financial_institution_name, '2'],
      ['EIN', reportData.financial_institution_ein, '3'],
      ['Address', reportData.financial_institution_address, '4'],
      ['City', reportData.financial_institution_city, '6'],
      ['State', reportData.financial_institution_state, '7'],
      ['ZIP Code', reportData.financial_institution_zip, '8'],
    ]);
    
    // Branch Information
    if (reportData.branch_address) {
      addSection('BRANCH OFFICE INFORMATION', [
        ['Branch Address', reportData.branch_address, '9'],
        ['Branch City', reportData.branch_city, '10'],
        ['Branch State', reportData.branch_state, '11'],
        ['Branch ZIP', reportData.branch_zip, '12'],
      ]);
    }
    
    // Account Information
    addSection('ACCOUNT INFORMATION', [
      ['Account Number(s)', reportData.account_number, '14'],
      ['Account Type', reportData.account_type, ''],
    ]);
    
    // Suspect Information
    addSection('PART II - SUSPECT INFORMATION', [
      ['Last Name/Entity Name', reportData.suspect_last_name || reportData.suspect_entity_name, '15'],
      ['First Name', reportData.suspect_first_name, '16'],
      ['Date of Birth', formatDateForPDF(reportData.suspect_date_of_birth), ''],
      ['Address', reportData.suspect_address, '18'],
      ['City', reportData.suspect_city, '20'],
      ['State', reportData.suspect_state, '21'],
      ['ZIP Code', reportData.suspect_zip, '22'],
      ['Phone Number', reportData.suspect_phone, '24'],
    ]);
    
    // Activity Information
    addSection('PART III - SUSPICIOUS ACTIVITY INFORMATION', [
      ['Activity Date', formatDateForPDF(reportData.suspicious_activity_date), '33'],
      ['Total Dollar Amount', `$${formatCurrencyForPDF(reportData.total_dollar_amount)}`, '34'],
      ['Activity Type', reportData.activity_type, ''],
      ['Activity Description', reportData.activity_description, ''],
    ]);
    
    // Footer
    const footerY = 50;
    page.drawText('This document contains SAR data for official use only.', {
      x: leftMargin,
      y: footerY,
      size: 8,
      font: font,
    });
    
    page.drawText('Please transfer this information to the official SAR form for submission.', {
      x: leftMargin,
      y: footerY - 12,
      size: 8,
      font: font,
    });
    
    const pdfBytes = await pdfDoc.save();
    return pdfBytes;
    
  } catch (error) {
    console.error('Error creating SAR data summary PDF:', error);
    throw error;
  }
}

// Helper function to wrap text
function wrapText(text, maxWidth, font, fontSize) {
  const words = text.split(' ');
  let line = '';
  let result = '';
  
  for (let i = 0; i < words.length; i++) {
    const testLine = line + words[i] + ' ';
    const testWidth = font.widthOfTextAtSize(testLine, fontSize);
    
    if (testWidth > maxWidth && i > 0) {
      result += line + '\n';
      line = words[i] + ' ';
    } else {
      line = testLine;
    }
  }
  result += line;
  
  return result.trim();
}

// Helper functions for PDF formatting
function formatDateForPDF(dateString) {
  if (!dateString) return '';
  
  try {
    const date = new Date(dateString);
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    const year = date.getFullYear();
    return `${month}/${day}/${year}`;
  } catch {
    return dateString;
  }
}

function formatCurrencyForPDF(amount) {
  if (!amount && amount !== 0) return '';
  
  const numAmount = typeof amount === 'string' ? parseFloat(amount) : amount;
  return numAmount.toFixed(2);
}

// Health check endpoint
app.get('/api/health', async (req, res) => {
  try {
    const health = await esClient.cluster.health();
    
    // Handle different Elasticsearch client response structures
    let status, numberOfNodes;
    
    if (health.body) {
      // Older client structure
      status = health.body.status;
      numberOfNodes = health.body.number_of_nodes;
    } else {
      // Newer client structure
      status = health.status;
      numberOfNodes = health.number_of_nodes;
    }
    
    res.json({
      status: 'healthy',
      elasticsearch: {
        cluster_status: status,
        number_of_nodes: numberOfNodes
      },
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Elasticsearch health check failed:', error.message);
    res.status(503).json({
      status: 'unhealthy',
      error: 'Cannot connect to Elasticsearch',
      details: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error: 'Internal Server Error',
    details: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not Found' });
});

// Start server
app.listen(PORT, () => {
  console.log('🚀 === SAR Management System Started ===');
  console.log(`🌐 Server running at: http://localhost:${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/api/health`);
  console.log('');
  console.log('✨ Features Available:');
  console.log('  📄 SAR PDF Generation (saved locally + download)');
  console.log('  📋 FinCEN 8300 XML Generation (saved locally + download)');
  console.log('  🔍 Enhanced Fuzzy Search');
  console.log('  📁 Generated Files API (/api/generated-files)');
  console.log('  📊 Elasticsearch Integration');
  console.log('');
  console.log('📁 Files saved to:', __dirname);
  console.log('🎯 Ready for BSA compliance workflows!');
});

module.exports = app;
