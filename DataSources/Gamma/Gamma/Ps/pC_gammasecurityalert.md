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
    """exabeam_host=({host}[^\s]{1,2000})""",
    """'file_labels_map':[^:]{1,2000}:\s{0,100}\['({event_name}[^']{1,2000})'""",
    """'dashboard_url':\s{0,100}'({additional_info}[^']{1,2000})'""",
    """'email_address':\s{0,100}'({user_email}[^@]{1,2000}@[^']{1,2000})'""",
    """'slack_user_id':\s{0,100}'({user_id}[^']{1,2000})'""",
    """'active_directory_user_id':\s{0,100}'({user_id}[^']{1,2000})'""",
    """'email_address':\s{0,100}'({user_email}[^']{1,2000})'""",
    """'github_handle':\s{0,100}'({user_id}[^']{1,2000})'""",
    """'violation_category':\s{0,100}'({alert_type}[^']{1,2000})'""",
    """'app_name':\s{0,100}'({app}[^']{1,2000})'""",
    """'violation_id':\s{0,100}({alert_id}[^,}]{1,2000})"""
  ]
}
```