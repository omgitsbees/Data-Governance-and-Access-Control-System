#!/usr/bin/env python3
"""
Data Governance and Access Control System
- Centralize data access policies and audit logging
- Integrate with LDAP/SSO for authentication
- Automate data access requests and approvals
"""

import json
import sqlite3
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
import ldap3
from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('data_governance.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Enums for better type safety
class AccessLevel(Enum):
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"
    DELETE = "delete"

class RequestStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"

class DataClassification(Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"

class AuditAction(Enum):
    ACCESS_GRANTED = "access_granted"
    ACCESS_DENIED = "access_denied"
    ACCESS_REVOKED = "access_revoked"
    POLICY_CREATED = "policy_created"
    POLICY_UPDATED = "policy_updated"
    POLICY_DELETED = "policy_deleted"
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    REQUEST_SUBMITTED = "request_submitted"
    REQUEST_APPROVED = "request_approved"
    REQUEST_REJECTED = "request_rejected"

# Data Classes
@dataclass
class User:
    id: str
    username: str
    email: str
    department: str
    role: str
    is_active: bool = True
    created_at: datetime = None
    last_login: datetime = None
    ldap_dn: str = None
    access_level: str = "standard"

@dataclass
class DataPolicy:
    id: str
    name: str
    description: str
    data_types: List[str]
    access_levels: List[str]
    classification: DataClassification
    approval_required: bool = True
    retention_period_days: int = 2555  # 7 years default
    created_at: datetime = None
    updated_at: datetime = None
    created_by: str = None

@dataclass
class AccessRequest:
    id: str
    requestor_id: str
    resource_name: str
    access_level: AccessLevel
    justification: str
    status: RequestStatus
    priority: str = "medium"
    data_classification: DataClassification = DataClassification.INTERNAL
    created_at: datetime = None
    approved_by: str = None
    approved_at: datetime = None
    expires_at: datetime = None
    department: str = None

@dataclass
class AuditLog:
    id: str
    timestamp: datetime
    user_id: str
    action: AuditAction
    resource: str
    ip_address: str
    user_agent: str
    result: str
    details: Dict[str, Any] = None

class LDAPAuthenticator:
    """LDAP/SSO Authentication Handler"""
    
    def __init__(self, ldap_server: str, base_dn: str, bind_user: str, bind_password: str):
        self.ldap_server = ldap_server
        self.base_dn = base_dn
        self.bind_user = bind_user
        self.bind_password = bind_password
        self.logger = logging.getLogger(__name__ + '.LDAPAuth')
    
    def authenticate(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate user against LDAP"""
        try:
            server = ldap3.Server(self.ldap_server, get_info=ldap3.ALL)
            conn = ldap3.Connection(server, self.bind_user, self.bind_password, auto_bind=True)
            
            # Search for user
            search_filter = f"(sAMAccountName={username})"
            conn.search(self.base_dn, search_filter, attributes=['mail', 'department', 'title'])
            
            if not conn.entries:
                return None
            
            user_entry = conn.entries[0]
            user_dn = user_entry.entry_dn
            
            # Try to bind with user credentials
            user_conn = ldap3.Connection(server, user_dn, password)
            if user_conn.bind():
                return {
                    'username': username,
                    'email': str(user_entry.mail.value) if user_entry.mail else f"{username}@company.com",
                    'department': str(user_entry.department.value) if user_entry.department else "Unknown",
                    'role': str(user_entry.title.value) if user_entry.title else "User",
                    'ldap_dn': user_dn
                }
            
            return None
            
        except Exception as e:
            self.logger.error(f"LDAP authentication failed: {str(e)}")
            return None
    
    def sync_users(self) -> List[Dict[str, Any]]:
        """Sync users from LDAP directory"""
        try:
            server = ldap3.Server(self.ldap_server, get_info=ldap3.ALL)
            conn = ldap3.Connection(server, self.bind_user, self.bind_password, auto_bind=True)
            
            # Search for all users
            search_filter = "(objectClass=user)"
            conn.search(self.base_dn, search_filter, 
                       attributes=['sAMAccountName', 'mail', 'department', 'title', 'userAccountControl'])
            
            users = []
            for entry in conn.entries:
                if entry.sAMAccountName:
                    # Check if account is disabled (userAccountControl & 2)
                    is_active = True
                    if entry.userAccountControl:
                        is_active = not (int(entry.userAccountControl.value) & 2)
                    
                    users.append({
                        'username': str(entry.sAMAccountName.value),
                        'email': str(entry.mail.value) if entry.mail else f"{entry.sAMAccountName}@company.com",
                        'department': str(entry.department.value) if entry.department else "Unknown",
                        'role': str(entry.title.value) if entry.title else "User",
                        'is_active': is_active,
                        'ldap_dn': entry.entry_dn
                    })
            
            return users
            
        except Exception as e:
            self.logger.error(f"LDAP sync failed: {str(e)}")
            return []

class DataGovernanceSystem:
    """Main Data Governance and Access Control System"""
    
    def __init__(self, db_path: str = "data_governance.db"):
        self.db_path = db_path
        self.logger = logging.getLogger(__name__ + '.DataGovernance')
        self.ldap_auth = None
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                department TEXT,
                role TEXT,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                ldap_dn TEXT,
                access_level TEXT DEFAULT 'standard'
            )
        ''')
        
        # Data policies table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS data_policies (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                data_types TEXT,
                access_levels TEXT,
                classification TEXT,
                approval_required BOOLEAN DEFAULT TRUE,
                retention_period_days INTEGER DEFAULT 2555,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_by TEXT
            )
        ''')
        
        # Access requests table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS access_requests (
                id TEXT PRIMARY KEY,
                requestor_id TEXT NOT NULL,
                resource_name TEXT NOT NULL,
                access_level TEXT NOT NULL,
                justification TEXT,
                status TEXT DEFAULT 'pending',
                priority TEXT DEFAULT 'medium',
                data_classification TEXT DEFAULT 'internal',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                approved_by TEXT,
                approved_at TIMESTAMP,
                expires_at TIMESTAMP,
                department TEXT,
                FOREIGN KEY (requestor_id) REFERENCES users (id)
            )
        ''')
        
        # Audit logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_logs (
                id TEXT PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id TEXT,
                action TEXT NOT NULL,
                resource TEXT,
                ip_address TEXT,
                user_agent TEXT,
                result TEXT,
                details TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        
        self.logger.info("Database initialized successfully")
    
    def configure_ldap(self, ldap_server: str, base_dn: str, bind_user: str, bind_password: str):
        """Configure LDAP authentication"""
        self.ldap_auth = LDAPAuthenticator(ldap_server, base_dn, bind_user, bind_password)
        self.logger.info("LDAP authentication configured")
    
    def authenticate_user(self, username: str, password: str, ip_address: str = None) -> Optional[User]:
        """Authenticate user via LDAP/SSO"""
        if not self.ldap_auth:
            self.logger.warning("LDAP not configured, falling back to local auth")
            return self._local_authenticate(username, password)
        
        ldap_user = self.ldap_auth.authenticate(username, password)
        if not ldap_user:
            self.audit_log(None, AuditAction.USER_LOGIN, "Authentication", ip_address, "", "FAILED")
            return None
        
        # Get or create user in local database
        user = self.get_user_by_username(username)
        if not user:
            user = self.create_user(
                username=ldap_user['username'],
                email=ldap_user['email'],
                department=ldap_user['department'],
                role=ldap_user['role'],
                ldap_dn=ldap_user['ldap_dn']
            )
        
        # Update last login
        self.update_user_last_login(user.id)
        self.audit_log(user.id, AuditAction.USER_LOGIN, "Authentication", ip_address, "", "SUCCESS")
        
        return user
    
    def _local_authenticate(self, username: str, password: str) -> Optional[User]:
        """Local authentication fallback"""
        # This would be implemented for local users
        # For now, return None to force LDAP authentication
        return None
    
    def create_user(self, username: str, email: str, department: str, role: str, ldap_dn: str = None) -> User:
        """Create a new user"""
        user_id = hashlib.md5(f"{username}_{datetime.now().isoformat()}".encode()).hexdigest()
        
        user = User(
            id=user_id,
            username=username,
            email=email,
            department=department,
            role=role,
            created_at=datetime.now(),
            ldap_dn=ldap_dn
        )
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (id, username, email, department, role, created_at, ldap_dn)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (user.id, user.username, user.email, user.department, user.role, user.created_at, user.ldap_dn))
        conn.commit()
        conn.close()
        
        self.logger.info(f"Created user: {username}")
        return user
    
    def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return User(
                id=row[0], username=row[1], email=row[2], department=row[3],
                role=row[4], is_active=bool(row[5]), created_at=row[6],
                last_login=row[7], ldap_dn=row[8], access_level=row[9]
            )
        return None
    
    def update_user_last_login(self, user_id: str):
        """Update user's last login timestamp"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET last_login = ? WHERE id = ?', (datetime.now(), user_id))
        conn.commit()
        conn.close()
    
    def create_data_policy(self, name: str, description: str, data_types: List[str], 
                          access_levels: List[str], classification: DataClassification,
                          approval_required: bool = True, retention_period_days: int = 2555,
                          created_by: str = None) -> DataPolicy:
        """Create a new data policy"""
        policy_id = hashlib.md5(f"{name}_{datetime.now().isoformat()}".encode()).hexdigest()
        
        policy = DataPolicy(
            id=policy_id,
            name=name,
            description=description,
            data_types=data_types,
            access_levels=access_levels,
            classification=classification,
            approval_required=approval_required,
            retention_period_days=retention_period_days,
            created_at=datetime.now(),
            updated_at=datetime.now(),
            created_by=created_by
        )
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO data_policies (id, name, description, data_types, access_levels, 
                                     classification, approval_required, retention_period_days, 
                                     created_at, updated_at, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (policy.id, policy.name, policy.description, json.dumps(policy.data_types),
              json.dumps(policy.access_levels), policy.classification.value,
              policy.approval_required, policy.retention_period_days,
              policy.created_at, policy.updated_at, policy.created_by))
        conn.commit()
        conn.close()
        
        self.audit_log(created_by, AuditAction.POLICY_CREATED, name, None, None, "SUCCESS")
        self.logger.info(f"Created data policy: {name}")
        return policy
    
    def submit_access_request(self, requestor_id: str, resource_name: str, access_level: AccessLevel,
                             justification: str, priority: str = "medium", 
                             data_classification: DataClassification = DataClassification.INTERNAL) -> AccessRequest:
        """Submit a new access request"""
        request_id = f"REQ-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        # Get requestor info
        requestor = self.get_user_by_id(requestor_id)
        department = requestor.department if requestor else "Unknown"
        
        access_request = AccessRequest(
            id=request_id,
            requestor_id=requestor_id,
            resource_name=resource_name,
            access_level=access_level,
            justification=justification,
            status=RequestStatus.PENDING,
            priority=priority,
            data_classification=data_classification,
            created_at=datetime.now(),
            expires_at=datetime.now() + timedelta(days=30),  # 30 days to approve
            department=department
        )
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO access_requests (id, requestor_id, resource_name, access_level, 
                                       justification, status, priority, data_classification, 
                                       created_at, expires_at, department)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (access_request.id, access_request.requestor_id, access_request.resource_name,
              access_request.access_level.value, access_request.justification,
              access_request.status.value, access_request.priority,
              access_request.data_classification.value, access_request.created_at,
              access_request.expires_at, access_request.department))
        conn.commit()
        conn.close()
        
        self.audit_log(requestor_id, AuditAction.REQUEST_SUBMITTED, resource_name, None, None, "SUCCESS")
        self.logger.info(f"Access request submitted: {request_id}")
        
        # Send notification to approvers
        self._notify_approvers(access_request)
        
        return access_request
    
    def approve_access_request(self, request_id: str, approved_by: str) -> bool:
        """Approve an access request"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE access_requests 
            SET status = ?, approved_by = ?, approved_at = ?
            WHERE id = ? AND status = ?
        ''', (RequestStatus.APPROVED.value, approved_by, datetime.now(), request_id, RequestStatus.PENDING.value))
        
        if cursor.rowcount > 0:
            conn.commit()
            conn.close()
            self.audit_log(approved_by, AuditAction.REQUEST_APPROVED, request_id, None, None, "SUCCESS")
            self.logger.info(f"Access request approved: {request_id}")
            return True
        
        conn.close()
        return False
    
    def reject_access_request(self, request_id: str, rejected_by: str) -> bool:
        """Reject an access request"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE access_requests 
            SET status = ?, approved_by = ?, approved_at = ?
            WHERE id = ? AND status = ?
        ''', (RequestStatus.REJECTED.value, rejected_by, datetime.now(), request_id, RequestStatus.PENDING.value))
        
        if cursor.rowcount > 0:
            conn.commit()
            conn.close()
            self.audit_log(rejected_by, AuditAction.REQUEST_REJECTED, request_id, None, None, "SUCCESS")
            self.logger.info(f"Access request rejected: {request_id}")
            return True
        
        conn.close()
        return False
    
    def get_user_by_id(self, user_id: str) -> Optional[User]:
        """Get user by ID"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return User(
                id=row[0], username=row[1], email=row[2], department=row[3],
                role=row[4], is_active=bool(row[5]), created_at=row[6],
                last_login=row[7], ldap_dn=row[8], access_level=row[9]
            )
        return None
    
    def get_pending_requests(self) -> List[AccessRequest]:
        """Get all pending access requests"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM access_requests WHERE status = ?', (RequestStatus.PENDING.value,))
        rows = cursor.fetchall()
        conn.close()
        
        requests = []
        for row in rows:
            requests.append(AccessRequest(
                id=row[0], requestor_id=row[1], resource_name=row[2],
                access_level=AccessLevel(row[3]), justification=row[4],
                status=RequestStatus(row[5]), priority=row[6],
                data_classification=DataClassification(row[7]),
                created_at=row[8], approved_by=row[9], approved_at=row[10],
                expires_at=row[11], department=row[12]
            ))
        
        return requests
    
    def audit_log(self, user_id: str, action: AuditAction, resource: str, 
                  ip_address: str = None, user_agent: str = None, result: str = "SUCCESS",
                  details: Dict[str, Any] = None):
        """Log audit event"""
        log_id = hashlib.md5(f"{user_id}_{action.value}_{datetime.now().isoformat()}".encode()).hexdigest()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO audit_logs (id, user_id, action, resource, ip_address, user_agent, result, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (log_id, user_id, action.value, resource, ip_address, user_agent, result, 
              json.dumps(details) if details else None))
        conn.commit()
        conn.close()
    
    def get_audit_logs(self, limit: int = 100) -> List[AuditLog]:
        """Get recent audit logs"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?', (limit,))
        rows = cursor.fetchall()
        conn.close()
        
        logs = []
        for row in rows:
            logs.append(AuditLog(
                id=row[0], timestamp=row[1], user_id=row[2],
                action=AuditAction(row[3]), resource=row[4],
                ip_address=row[5], user_agent=row[6], result=row[7],
                details=json.loads(row[8]) if row[8] else None
            ))
        
        return logs
    
    def _notify_approvers(self, access_request: AccessRequest):
        """Send notifications to approvers"""
        # This would integrate with email/notification system
        self.logger.info(f"Notification sent for access request: {access_request.id}")
    
    def sync_ldap_users(self):
        """Sync users from LDAP directory"""
        if not self.ldap_auth:
            self.logger.warning("LDAP not configured, skipping sync")
            return
        
        ldap_users = self.ldap_auth.sync_users()
        
        for ldap_user in ldap_users:
            existing_user = self.get_user_by_username(ldap_user['username'])
            if not existing_user:
                self.create_user(
                    username=ldap_user['username'],
                    email=ldap_user['email'],
                    department=ldap_user['department'],
                    role=ldap_user['role'],
                    ldap_dn=ldap_user['ldap_dn']
                )
        
        self.logger.info(f"Synced {len(ldap_users)} users from LDAP")
    
    def generate_compliance_report(self) -> Dict[str, Any]:
        """Generate compliance and audit report"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get statistics
        cursor.execute('SELECT COUNT(*) FROM users WHERE is_active = 1')
        active_users = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM access_requests WHERE status = ?', (RequestStatus.PENDING.value,))
        pending_requests = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM data_policies')
        total_policies = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM audit_logs WHERE timestamp > ?', (datetime.now() - timedelta(days=30),))
        recent_audit_events = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'generated_at': datetime.now().isoformat(),
            'active_users': active_users,
            'pending_requests': pending_requests,
            'total_policies': total_policies,
            'recent_audit_events': recent_audit_events,
            'compliance_status': 'GREEN' if pending_requests < 10 else 'YELLOW'
        }

# CLI Interface
def main():
    """Main CLI interface for the Data Governance System"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Data Governance and Access Control System')
    parser.add_argument('--init', action='store_true', help='Initialize the system')
    parser.add_argument('--ldap-server', help='LDAP server URL')
    parser.add_argument('--ldap-base-dn', help='LDAP base DN')
    parser.add_argument('--ldap-bind-user', help='LDAP bind user')
    parser.add_argument('--ldap-bind-password', help='LDAP bind password')
    parser.add_argument('--sync-ldap', action='store_true', help='Sync users from LDAP')
    parser.add_argument('--report', action='store_true', help='Generate compliance report')
    
    args = parser.parse_args()
    
    # Initialize system
    dgs = DataGovernanceSystem()
    
    if args.init:
        print("Data Governance System initialized successfully!")
        
        # Create sample data policy
        dgs.create_data_policy(
            name="Customer Data Access Policy",
            description="Governs access to customer personal information",
            data_types=["PII", "Contact Information", "Purchase History"],
            access_levels=[AccessLevel.READ.value, AccessLevel.WRITE.value],
            classification=DataClassification.CONFIDENTIAL,
            approval_required=True,
            retention_period_days=2555,  # 7 years
            created_by="system"
        )
        
        print("Sample data policy created!")
    
    if args.ldap_server and args.ldap_base_dn and args.ldap_bind_user and args.ldap_bind_password:
        dgs.configure_ldap(args.ldap_server, args.ldap_base_dn, args.ldap_bind_user, args.ldap_bind_password)
        print("LDAP configuration updated!")
    
    if args.sync_ldap:
        dgs.sync_ldap_users()
        print("LDAP users synchronized!")
    
    if args.report:
        report = dgs.generate_compliance_report()
        print("\n=== COMPLIANCE REPORT ===")
        print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()