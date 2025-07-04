# Data Governance and Access Control System

A comprehensive Python-based data governance platform that centralizes data access policies, integrates with LDAP/SSO authentication, and automates data access requests and approvals.

## Features

- **Centralized Data Access Policies**: Define and manage data governance policies with classification levels and access controls
- **LDAP/SSO Integration**: Seamless authentication and user synchronization with Active Directory
- **Automated Access Request Workflow**: Submit, review, and approve data access requests with built-in notifications
- **Comprehensive Audit Logging**: Track all user actions and system events for compliance and security
- **Compliance Reporting**: Generate detailed reports on system usage and policy compliance
- **Role-Based Access Control**: Manage user permissions based on department and role assignments

## Installation

### Prerequisites

- Python 3.8 or higher
- SQLite3
- LDAP server (optional, for SSO integration)

### Dependencies

```bash
pip install -r requirements.txt
```

Required packages:
```
Flask==2.3.3
Flask-SQLAlchemy==3.0.5
ldap3==2.9.1
PyJWT==2.8.0
Werkzeug==2.3.7
```

### Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/data-governance-system.git
cd data-governance-system
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Initialize the system:
```bash
python data_governance.py --init
```

## Configuration

### LDAP Integration

Configure LDAP authentication for enterprise SSO:

```bash
python data_governance.py --ldap-server "ldaps://dc.company.com" \
                         --ldap-base-dn "DC=company,DC=com" \
                         --ldap-bind-user "cn=admin,cn=users,dc=company,dc=com" \
                         --ldap-bind-password "your_password"
```

### Environment Variables

Create a `.env` file in the project root:

```env
DATABASE_URL=sqlite:///data_governance.db
LDAP_SERVER=ldaps://dc.company.com
LDAP_BASE_DN=DC=company,DC=com
LDAP_BIND_USER=cn=admin,cn=users,dc=company,dc=com
LDAP_BIND_PASSWORD=your_password
SECRET_KEY=your_secret_key_here
SMTP_SERVER=smtp.company.com
SMTP_PORT=587
SMTP_USERNAME=notifications@company.com
SMTP_PASSWORD=smtp_password
```

## Usage

### Command Line Interface

#### Initialize System
```bash
python data_governance.py --init
```

#### Sync Users from LDAP
```bash
python data_governance.py --sync-ldap
```

#### Generate Compliance Report
```bash
python data_governance.py --report
```

### Python API

#### Basic Usage Example

```python
from data_governance import DataGovernanceSystem, AccessLevel, DataClassification

# Initialize system
dgs = DataGovernanceSystem()

# Configure LDAP
dgs.configure_ldap(
    ldap_server="ldaps://dc.company.com",
    base_dn="DC=company,DC=com",
    bind_user="cn=admin,cn=users,dc=company,dc=com",
    bind_password="password"
)

# Authenticate user
user = dgs.authenticate_user("john.doe", "password", "192.168.1.100")

# Create data policy
policy = dgs.create_data_policy(
    name="Customer Data Access Policy",
    description="Governs access to customer personal information",
    data_types=["PII", "Contact Information", "Purchase History"],
    access_levels=[AccessLevel.READ.value, AccessLevel.WRITE.value],
    classification=DataClassification.CONFIDENTIAL,
    approval_required=True,
    retention_period_days=2555,
    created_by=user.id
)

# Submit access request
request = dgs.submit_access_request(
    requestor_id=user.id,
    resource_name="Customer Database",
    access_level=AccessLevel.READ,
    justification="Monthly reporting requirements",
    priority="medium",
    data_classification=DataClassification.CONFIDENTIAL
)

# Approve request
dgs.approve_access_request(request.id, approver_user_id)
```

## Data Models

### User
```python
@dataclass
class User:
    id: str
    username: str
    email: str
    department: str
    role: str
    is_active: bool
    created_at: datetime
    last_login: datetime
    ldap_dn: str
    access_level: str
```

### Data Policy
```python
@dataclass
class DataPolicy:
    id: str
    name: str
    description: str
    data_types: List[str]
    access_levels: List[str]
    classification: DataClassification
    approval_required: bool
    retention_period_days: int
    created_at: datetime
    updated_at: datetime
    created_by: str
```

### Access Request
```python
@dataclass
class AccessRequest:
    id: str
    requestor_id: str
    resource_name: str
    access_level: AccessLevel
    justification: str
    status: RequestStatus
    priority: str
    data_classification: DataClassification
    created_at: datetime
    approved_by: str
    approved_at: datetime
    expires_at: datetime
    department: str
```

## Data Classifications

The system supports four levels of data classification:

- **PUBLIC**: Information that can be freely shared
- **INTERNAL**: Information restricted to company employees
- **CONFIDENTIAL**: Sensitive information requiring approval
- **RESTRICTED**: Highly sensitive information with strict access controls

## Access Levels

Available access levels for data resources:

- **READ**: View-only access to data
- **WRITE**: Ability to modify existing data
- **ADMIN**: Full administrative access including user management
- **DELETE**: Permission to remove data (highest level)

## Audit Events

The system tracks the following audit events:

- User authentication (login/logout)
- Access granted/denied/revoked
- Policy creation/updates/deletion
- Access request submission/approval/rejection
- User management actions
- System configuration changes

## Database Schema

The system uses SQLite by default with the following tables:

- `users`: User account information and LDAP integration
- `data_policies`: Data governance policies and rules
- `access_requests`: Access request workflow and approvals
- `audit_logs`: Comprehensive audit trail of all system events

## Security Features

- **LDAP/SSO Integration**: Enterprise authentication with Active Directory
- **Role-Based Access Control**: Granular permissions based on user roles
- **Audit Logging**: Complete trail of all system activities
- **Data Classification**: Multiple levels of data sensitivity
- **Request Approval Workflow**: Mandatory approval for sensitive data access
- **Session Management**: Secure session handling with JWT tokens
- **IP Address Tracking**: Monitor access locations for security

## Compliance

The system supports compliance with various regulations:

- **GDPR**: Data retention policies and access controls
- **SOX**: Audit trails and access approval workflows
- **HIPAA**: Data classification and access logging
- **ISO 27001**: Information security management

## API Documentation

### Authentication Endpoints

- `POST /api/auth/login` - User authentication
- `POST /api/auth/logout` - User logout
- `GET /api/auth/profile` - Get user profile

### Access Request Endpoints

- `POST /api/requests` - Submit access request
- `GET /api/requests` - List access requests
- `PUT /api/requests/{id}/approve` - Approve request
- `PUT /api/requests/{id}/reject` - Reject request

### Policy Management Endpoints

- `POST /api/policies` - Create data policy
- `GET /api/policies` - List data policies
- `PUT /api/policies/{id}` - Update policy
- `DELETE /api/policies/{id}` - Delete policy

### Audit Endpoints

- `GET /api/audit/logs` - Retrieve audit logs
- `GET /api/audit/report` - Generate compliance report

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-feature`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/new-feature`)
5. Create a Pull Request

### Development Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/data-governance-system.git
cd data-governance-system

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Run linting
flake8 data_governance.py
black data_governance.py
```

## Testing

Run the test suite:

```bash
# Run all tests
python -m pytest

# Run with coverage
python -m pytest --cov=data_governance

# Run specific test file
python -m pytest tests/test_authentication.py
```

## Deployment

### Docker Deployment

```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 5000
CMD ["python", "app.py"]
```

### Production Considerations

- Use PostgreSQL or MySQL for production databases
- Configure proper SSL/TLS certificates
- Set up log rotation and monitoring
- Implement backup and disaster recovery procedures
- Configure firewall rules and network security
- Set up monitoring and alerting systems

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
