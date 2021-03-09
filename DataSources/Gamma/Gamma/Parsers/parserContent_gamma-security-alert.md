#### Parser Content
```Java
{
Name = gamma-security-alert
  Vendor = Gamma
  Product = Gamma
  Lms = Splunk
  DataType = "security-alert"
  TimeFormat = "epoch"
  Conditions = [ """'violation_status': """, """'violation_category': """, """'violation_id':""", """'violation_event_timestamp':""" ]
  Fields = [
    """'violation_event_timestamp':\s*({time}\d+)""",
    """exabeam_host=({host}[^\s]+)""",
    """'file_labels_map':[^:]+:\s*\['({event_name}[^']+)'""",
    """'dashboard_url':\s*'({additional_info}[^']+)'""",
    """'email_address':\s*'({user_email}[^@]+@[^']+)'""",
    """'slack_user_id':\s*'({user_id}[^']+)'""",
    """'active_directory_user_id':\s*'({user_id}[^']+)'""",
    """'email_address':\s*'({user_email}[^']+)'""",
    """'github_handle':\s*'({user_id}[^']+)'""",
    """'violation_category':\s*'({alert_type}[^']+)'""",
    """'app_name':\s*'({app}[^']+)'""",
    """'violation_id':\s*({alert_id}[^,}]+)"""
  ]
}
```