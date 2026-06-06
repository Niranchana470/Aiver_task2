"""Finding Database for Lifecycle Tracking"""
import sqlite3
import json
from typing import Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum


class FindingStatus(Enum):
    """Finding lifecycle status"""
    OPENED = "Opened"
    UPDATED = "Updated"
    RESOLVED = "Resolved"
    IGNORED = "Ignored"
    FALSE_POSITIVE = "False Positive"


@dataclass
class FindingRecord:
    """Database record for security finding"""
    id: Optional[int]
    finding_hash: str
    check_name: str
    resource_arn: str
    severity: str
    title: str
    description: str
    business_impact: str
    confidence: float
    status: FindingStatus
    first_seen: datetime
    last_seen: datetime
    remediation: str
    evidence: str  # JSON string
    metadata: str   # JSON string
    notes: Optional[str] = None
    resolved_at: Optional[datetime] = None
    sla_deadline: Optional[datetime] = None


class FindingDatabase:
    """
    SQLite database for tracking finding lifecycle
    """
    
    def __init__(self, db_path: str = "findings.db"):
        self.db_path = db_path
        self.conn = None
        self._initialize_db()
    
    def _initialize_db(self):
        """Initialize database schema"""
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.execute("PRAGMA foreign_keys = ON")
        
        # Create findings table
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_hash TEXT UNIQUE NOT NULL,
                check_name TEXT NOT NULL,
                resource_arn TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                business_impact TEXT,
                confidence REAL,
                status TEXT NOT NULL,
                first_seen TIMESTAMP NOT NULL,
                last_seen TIMESTAMP NOT NULL,
                remediation TEXT,
                evidence TEXT,
                metadata TEXT,
                notes TEXT,
                resolved_at TIMESTAMP,
                sla_deadline TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create finding_history table for audit trail
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS finding_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                notes TEXT,
                FOREIGN KEY (finding_id) REFERENCES findings(id)
            )
        """)
        
        # Create indexes for common queries
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_finding_hash 
            ON findings(finding_hash)
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_severity 
            ON findings(severity)
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_status 
            ON findings(status)
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_last_seen 
            ON findings(last_seen)
        """)
        
        self.conn.commit()
    
    def store_finding(self, finding: Dict[str, Any]) -> int:
        """
        Store or update a finding in the database
        Returns finding ID
        """
        import hashlib
        
        # Create hash for deduplication
        finding_hash = hashlib.md5(
            f"{finding.get('check_name')}|{finding.get('resource_arn')}|{finding.get('title')}".encode()
        ).hexdigest()
        
        # Check if finding exists
        existing = self.conn.execute(
            "SELECT id, status FROM findings WHERE finding_hash = ?",
            (finding_hash,)
        ).fetchone()
        
        now = datetime.utcnow()
        
        if existing:
            finding_id, current_status = existing
            
            # Update existing finding
            self.conn.execute("""
                UPDATE findings 
                SET last_seen = ?,
                    status = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (now, FindingStatus.UPDATED.value, finding_id))
            
            # Add to history
            self.conn.execute("""
                INSERT INTO finding_history (finding_id, status, notes)
                VALUES (?, ?, ?)
            """, (finding_id, FindingStatus.UPDATED.value, "Finding reoccurred in scan"))
            
            self.conn.commit()
            return finding_id
        else:
            # Insert new finding
            sla_deadline = self._calculate_sla_deadline(finding.get("severity", "Info"))
            
            cursor = self.conn.execute("""
                INSERT INTO findings (
                    finding_hash, check_name, resource_arn, severity, title,
                    description, business_impact, confidence, status,
                    first_seen, last_seen, remediation, evidence, metadata,
                    sla_deadline
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                finding_hash,
                finding.get("check_name"),
                finding.get("resource_arn"),
                finding.get("severity"),
                finding.get("title"),
                finding.get("description"),
                finding.get("business_impact"),
                finding.get("confidence"),
                FindingStatus.OPENED.value,
                now,
                now,
                finding.get("remediation"),
                json.dumps(finding.get("evidence", {})),
                json.dumps(finding.get("metadata", {})),
                sla_deadline
            ))
            
            finding_id = cursor.lastrowid
            
            # Add to history
            self.conn.execute("""
                INSERT INTO finding_history (finding_id, status, notes)
                VALUES (?, ?, ?)
            """, (finding_id, FindingStatus.OPENED.value, "New finding detected"))
            
            self.conn.commit()
            return finding_id
    
    def get_finding(self, finding_hash: str) -> Optional[FindingRecord]:
        """Get a finding by hash"""
        row = self.conn.execute(
            "SELECT * FROM findings WHERE finding_hash = ?",
            (finding_hash,)
        ).fetchone()
        
        if row:
            return self._row_to_finding_record(row)
        return None
    
    def get_findings_by_status(self, status: FindingStatus) -> List[FindingRecord]:
        """Get all findings with a specific status"""
        rows = self.conn.execute(
            "SELECT * FROM findings WHERE status = ? ORDER BY last_seen DESC",
            (status.value,)
        ).fetchall()
        
        return [self._row_to_finding_record(row) for row in rows]
    
    def get_findings_past_sla(self) -> List[FindingRecord]:
        """Get findings that have exceeded their SLA deadline"""
        now = datetime.utcnow()
        rows = self.conn.execute("""
            SELECT * FROM findings 
            WHERE status NOT IN ('Resolved', 'Ignored', 'False Positive')
            AND sla_deadline < ?
            ORDER BY sla_deadline ASC
        """, (now,)).fetchall()
        
        return [self._row_to_finding_record(row) for row in rows]
    
    def update_finding_status(
        self,
        finding_hash: str,
        new_status: FindingStatus,
        notes: Optional[str] = None
    ) -> bool:
        """Update the status of a finding"""
        existing = self.conn.execute(
            "SELECT id FROM findings WHERE finding_hash = ?",
            (finding_hash,)
        ).fetchone()
        
        if not existing:
            return False
        
        finding_id = existing[0]
        
        # Update finding
        update_fields = {"status": new_status.value}
        if new_status == FindingStatus.RESOLVED:
            update_fields["resolved_at"] = datetime.utcnow()
        
        # Build UPDATE query dynamically
        set_clause = ", ".join(f"{k} = ?" for k in update_fields.keys())
        values = list(update_fields.values()) + [finding_id]
        
        self.conn.execute(
            f"UPDATE findings SET {set_clause} WHERE id = ?",
            values
        )
        
        # Add to history
        self.conn.execute("""
            INSERT INTO finding_history (finding_id, status, notes)
            VALUES (?, ?, ?)
        """, (finding_id, new_status.value, notes or "Status updated"))
        
        self.conn.commit()
        return True
    
    def get_security_posture_score(self, days: int = 30) -> Dict[str, Any]:
        """
        Calculate security posture score based on findings history
        """
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        # Get findings in the period
        rows = self.conn.execute("""
            SELECT severity, status, first_seen, resolved_at
            FROM findings
            WHERE first_seen >= ?
            ORDER BY first_seen ASC
        """, (cutoff_date,)).fetchall()
        
        # Calculate metrics
        severity_weights = {
            "Critical": 10,
            "High": 5,
            "Medium": 2,
            "Low": 1,
            "Info": 0.5
        }
        
        total_risk_score = 0
        resolved_count = 0
        open_count = 0
        
        severity_breakdown = {
            "Critical": {"opened": 0, "resolved": 0},
            "High": {"opened": 0, "resolved": 0},
            "Medium": {"opened": 0, "resolved": 0},
            "Low": {"opened": 0, "resolved": 0},
            "Info": {"opened": 0, "resolved": 0}
        }
        
        for severity, status, first_seen, resolved_at in rows:
            if severity in severity_breakdown:
                if status == "Resolved":
                    severity_breakdown[severity]["resolved"] += 1
                    resolved_count += 1
                else:
                    severity_breakdown[severity]["opened"] += 1
                    open_count += 1
                    total_risk_score += severity_weights.get(severity, 0)
        
        # Calculate posture score (0-100, higher is better)
        total_findings = len(rows)
        if total_findings == 0:
            posture_score = 100
        else:
            resolution_rate = resolved_count / total_findings
            risk_penalty = min(total_risk_score / 100, 1.0)
            posture_score = int((resolution_rate * 70) + ((1 - risk_penalty) * 30))
        
        return {
            "posture_score": posture_score,
            "trend_days": days,
            "total_findings": total_findings,
            "open_findings": open_count,
            "resolved_findings": resolved_count,
            "resolution_rate": round(resolved_count / total_findings * 100, 1) if total_findings > 0 else 100,
            "total_risk_score": total_risk_score,
            "severity_breakdown": severity_breakdown
        }
    
    def get_posture_history(self, days: int = 90) -> List[Dict[str, Any]]:
        """
        Get security posture score history over time
        """
        history = []
        
        for day in range(days, 0, -7):  # Weekly intervals
            cutoff_date = datetime.utcnow() - timedelta(days=day)
            score_data = self.get_security_posture_score(days=day)
            
            history.append({
                "date": cutoff_date.isoformat(),
                "posture_score": score_data["posture_score"],
                "open_findings": score_data["open_findings"],
                "resolved_findings": score_data["resolved_findings"]
            })
        
        return history
    
    def _calculate_sla_deadline(self, severity: str) -> Optional[datetime]:
        """Calculate SLA deadline based on severity"""
        sla_hours = {
            "Critical": 24,
            "High": 72,      # 3 days
            "Medium": 168,   # 7 days
            "Low": 720,      # 30 days
            "Info": None
        }
        
        hours = sla_hours.get(severity)
        if hours:
            return datetime.utcnow() + timedelta(hours=hours)
        return None
    
    def _row_to_finding_record(self, row) -> FindingRecord:
        """Convert database row to FindingRecord"""
        return FindingRecord(
            id=row[0],
            finding_hash=row[1],
            check_name=row[2],
            resource_arn=row[3],
            severity=row[4],
            title=row[5],
            description=row[6],
            business_impact=row[7],
            confidence=row[8],
            status=FindingStatus(row[9]),
            first_seen=datetime.fromisoformat(row[10]),
            last_seen=datetime.fromisoformat(row[11]),
            remediation=row[12],
            evidence=row[13],
            metadata=row[14],
            notes=row[15],
            resolved_at=datetime.fromisoformat(row[16]) if row[16] else None,
            sla_deadline=datetime.fromisoformat(row[17]) if row[17] else None
        )
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()