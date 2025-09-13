#!/usr/bin/env python3
"""
Debug script to check reports in database
"""

import sqlite3
import os

def check_reports():
    """Check all reports in the database"""
    db_path = "users.db"
    
    if not os.path.exists(db_path):
        print("❌ Database file not found!")
        return
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check all reports
        cursor.execute("SELECT * FROM reports ORDER BY created_at DESC")
        reports = cursor.fetchall()
        
        print(f"📊 Total reports in database: {len(reports)}")
        print("\n" + "="*80)
        
        if reports:
            print("All Reports:")
            for i, report in enumerate(reports, 1):
                print(f"\n{i}. Report ID: {report[0]}")
                print(f"   Location: {report[1]}")
                print(f"   Is Street: {report[2]}")
                print(f"   Quality: {report[3]}")
                print(f"   Created: {report[4]}")
                print(f"   User ID: {report[5]}")
        else:
            print("❌ No reports found in database")
        
        # Check users
        cursor.execute("SELECT id, name, email FROM users")
        users = cursor.fetchall()
        
        print(f"\n📊 Total users in database: {len(users)}")
        print("\nAll Users:")
        for user in users:
            print(f"   User ID: {user[0]}, Name: {user[1]}, Email: {user[2]}")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Error checking reports: {e}")

if __name__ == "__main__":
    check_reports()
