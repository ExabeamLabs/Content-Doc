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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"timestamp": ({time}\d{1,100})""",
    """"user": "(?![^\s]{1,2000}@[^\s]{1,2000})({user}[^"\s]{1,2000})"""",
    """"user": "(?=[^\s]{1,2000}@[^\s]{1,2000})({user_email}[^"\s@]{1,2000}@({email_domain}[^"\s@]{1,2000}))"""",
  ]
}
```