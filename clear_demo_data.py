#!/usr/bin/env python3
"""
Script to clear demo/test data from the FixZen database
Run this to remove all existing reports that weren't submitted by actual users
"""

import sqlite3
import os

def clear_demo_reports():
    """Clear all reports with user_id = None (demo data)"""
    db_path = "users.db"
    
    if not os.path.exists(db_path):
        print("Database file not found!")
        return
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Count existing demo reports
        cursor.execute("SELECT COUNT(*) FROM reports WHERE user_id IS NULL")
        demo_count = cursor.fetchone()[0]
        
        if demo_count > 0:
            print(f"Found {demo_count} demo reports. Clearing...")
            
            # Delete all reports with no user_id (demo data)
            cursor.execute("DELETE FROM reports WHERE user_id IS NULL")
            
            # Count remaining reports
            cursor.execute("SELECT COUNT(*) FROM reports")
            remaining_count = cursor.fetchone()[0]
            
            conn.commit()
            print(f"✅ Cleared {demo_count} demo reports")
            print(f"📊 {remaining_count} user reports remaining")
        else:
            print("No demo reports found to clear")
            
        conn.close()
        
    except Exception as e:
        print(f"❌ Error clearing demo data: {e}")

if __name__ == "__main__":
    clear_demo_reports()
