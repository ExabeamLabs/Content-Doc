#### Parser Content
```Java
{
Name = s-netskope-login
  Vendor = Netskope
  Product = Netskope Active Platform
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "epoch_sec"
  Conditions = [ """"type": "admin_audit_logs"""", """"audit_log_event":""", """Login Successful"""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"timestamp": ({time}\d+)""",
    """"user": "(?![^\s]+@[^\s]+)({user}[^"\s]+)"""",
    """"user": "(?=[^\s]+@[^\s]+)({user_email}[^"\s@]+@({email_domain}[^"\s@]+))"""",
  ]
}
```