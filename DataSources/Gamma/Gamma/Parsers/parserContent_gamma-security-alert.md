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
    """'violation_event_timestamp':\s{0,100}({time}\d{1,100})""",
    """exabeam_host=({host}[^\s]+)""",
    """'file_labels_map':[^:]+:\s{0,100}\['({event_name}[^']+)'""",
    """'dashboard_url':\s{0,100}'({additional_info}[^']+)'""",
    """'email_address':\s{0,100}'({user_email}[^@]+@[^']+)'""",
    """'slack_user_id':\s{0,100}'({user_id}[^']+)'""",
    """'active_directory_user_id':\s{0,100}'({user_id}[^']+)'""",
    """'email_address':\s{0,100}'({user_email}[^']+)'""",
    """'github_handle':\s{0,100}'({user_id}[^']+)'""",
    """'violation_category':\s{0,100}'({alert_type}[^']+)'""",
    """'app_name':\s{0,100}'({app}[^']+)'""",
    """'violation_id':\s{0,100}({alert_id}[^,}]+)"""
  ]
}
```