#### Parser Content
```Java
{
Name = s-netskope-activity
  Vendor = Netskope
  Product = Netskope Active Platform
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "epoch_sec"
  Conditions = [ """"type": "admin_audit_logs"""", """"audit_log_event":""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"timestamp": ({time}\d+)""",
    """"audit_log_event": "({activity}[^"]+)"""",
    """"user": "(?![^\s]+@[^\s]+)({user}[^"\s]+)"""",
    """"user": "(?=[^\s]+@[^\s]+)({user_email}[^"\s@]+@({email_domain}[^"\s@]+))"""",
  ]
  DupFields = [ "activity->accesses" ]
}
```