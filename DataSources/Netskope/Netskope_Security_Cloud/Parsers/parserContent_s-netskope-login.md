#### Parser Content
```Java
{
Name = s-netskope-login
  Vendor = Netskope
  Product = Netskope Security Cloud
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "epoch_sec"
  Conditions = [ """"type": "admin_audit_logs"""", """"audit_log_event":""", """Login Successful"""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"timestamp": ({time}\d{1,100})""",
    """"user": "(?![^\s]+@[^\s]+)({user}[^"\s]+)"""",
    """"user": "(?=[^\s]+@[^\s]+)({user_email}[^"\s@]+@({email_domain}[^"\s@]+))"""",
  ]
}
```