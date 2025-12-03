# SAR Management System

A professional web-based Suspicious Activity Report (SAR) management system that displays and manages SAR data from Elasticsearch with a compliance-focused interface.

## 🌟 Features

- **Professional Web Interface** - Clean, trustworthy design suitable for financial compliance
- **Elasticsearch Integration** - Real-time data retrieval with full-text search capabilities
- **SAR Field Mapping** - Direct mapping to official SAR PDF template fields (2, 3, 4, 6-12, 14-16, 18, 20-22, 24, 33-34)
- **Advanced Search & Filter** - Search across multiple fields with pagination
- **Responsive Design** - Works seamlessly on desktop and mobile devices
- **Security Features** - Rate limiting, CORS protection, input sanitization
- **Health Monitoring** - Real-time system status and connectivity checks
- **RESTful API** - Complete API for integration with other systems

## 📋 SAR PDF Field Mapping

The system automatically maps Elasticsearch data to these official SAR template fields:

### Financial Institution Information
- **Field 2**: `financial_institution_name` - Name of Financial Institution
- **Field 3**: `financial_institution_ein` - EIN
- **Field 4**: `financial_institution_address` - Address of Financial Institution
- **Fields 6-8**: `financial_institution_city`, `financial_institution_state`, `financial_institution_zip`

### Branch Office Information
- **Fields 9-12**: `branch_address`, `branch_city`, `branch_state`, `branch_zip`

### Account & Suspect Information
- **Field 14**: `account_number` - Account number(s) affected
- **Fields 15-16**: `suspect_last_name`/`suspect_entity_name`, `suspect_first_name`
- **Fields 18, 20-22, 24**: Address, city, state, zip, phone information

### Activity Information
- **Field 33**: `suspicious_activity_date` - Date or date range of suspicious activity
- **Field 34**: `total_dollar_amount` - Total dollar amount involved

## 🚀 Quick Start

### Prerequisites

- Node.js 16+ and npm
- Elasticsearch cluster with SAR data
- Linux/macOS (Ubuntu 18.04+ recommended)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/sar-management-system.git
   cd sar-management-system
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Configure environment:**
   ```bash
   cp .env.example .env
   # Edit .env with your Elasticsearch settings
   ```

4. **Set up Elasticsearch index:**
   ```bash
   # Create index with proper mapping
   curl -X PUT "http://kubernetes-vm:30920/sar-reports" \
     -H "Content-Type: application/json" \
     -d @elasticsearch-mapping.json \
     -u "fraud:hunter"
   ```

5. **Load sample data (optional):**
   ```bash
   ./load-sample-data.sh
   ```

6. **Start the application:**
   ```bash
   npm start
   ```

7. **Access the interface:**
   Open `http://localhost:3000`

### Automated Installation

For automated setup:

```bash
chmod +x install_sar_system.sh
./install_sar_system.sh --sample-data
```

## ⚙️ Configuration

Create a `.env` file with your configuration:

```bash
# Server Configuration
PORT=3000
NODE_ENV=production

# Elasticsearch Configuration
ELASTICSEARCH_URL=https://your-elasticsearch-cluster:9200
ELASTICSEARCH_USERNAME=your-username
ELASTICSEARCH_PASSWORD=your-password
ELASTICSEARCH_INDEX=sar-reports

# Security
SESSION_SECRET=your-secure-random-string
```

## 📡 API Endpoints

- `GET /api/sar-reports` - List SAR reports with pagination and search
- `GET /api/sar-reports/:id` - Get specific SAR report details
- `GET /api/health` - System health check

### Example API Usage

```bash
# Get all reports
curl http://localhost:3000/api/sar-reports

# Search for reports
curl "http://localhost:3000/api/sar-reports?search=smith&page=1&size=10"

# Check system health
curl http://localhost:3000/api/health
```

## 🔒 Security Features

- **Rate Limiting** - API endpoint protection
- **Input Sanitization** - XSS and injection prevention
- **CORS Protection** - Cross-origin request security
- **Helmet.js** - Security headers
- **Environment Variables** - Secure credential management

## 📊 Sample Data Structure

```json
{
  "@timestamp": "2024-01-15T10:30:00Z",
  "financial_institution_name": "Example Bank",
  "financial_institution_ein": "12-3456789",
  "suspect_last_name": "Smith",
  "suspect_first_name": "John",
  "suspicious_activity_date": "2024-01-10",
  "total_dollar_amount": 50000.00,
  "activity_description": "Structured transactions to avoid reporting requirements"
}
```

## 🏗️ Architecture

```
├── server.js              # Express.js server
├── public/                # Static assets
│   ├── css/styles.css     # Application styling
│   └── js/app.js          # Frontend JavaScript
├── views/                 # EJS templates
├── elasticsearch-mapping.json  # ES index mapping
└── sample-sar-data.json   # Sample data for testing
```

## 🛠️ Development

```bash
# Development mode with auto-restart
npm run dev

# Production mode
npm start

# Install new dependencies
npm install package-name
```

## 🔧 Troubleshooting

**Cannot connect to Elasticsearch:**
- Verify ELASTICSEARCH_URL in .env
- Check credentials and network connectivity
- Test connection: `curl -u user:pass http://your-es:9200/_cluster/health`

**No reports showing:**
- Verify index name matches ELASTICSEARCH_INDEX
- Check if data exists in Elasticsearch
- Review mapping compatibility

**System health shows errors:**
- Check Elasticsearch cluster status
- Verify index exists and is accessible
- Review application logs

## 📜 License

This project is licensed under the ISC License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📞 Support

- Create an [Issue](https://github.com/yourusername/sar-management-system/issues) for bug reports or feature requests
- See [WORKSHOP.md](WORKSHOP.md) for workshop-specific setup instructions

## ⚠️ Security Notice

This system handles sensitive financial data. Always follow your organization's security policies and regulatory requirements when deploying to production environments.

---

**Note**: This system is designed for legitimate compliance and regulatory purposes only. Ensure proper authorization and adherence to all applicable laws and regulations when handling suspicious activity data.
