#### Parser Content
```Java
{
Name = s-symantec-auth-failed
  Vendor = Symantec
  Product = Symantec VIP
  Lms = Splunk
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS z"
  Conditions = [ """StatusMessage: Authentication Failed""" ]
  Fields = [ 
    """INFO.*?({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d\.\d\d\d \w+(\+|\-)\d{1,100})\s{0,100}"\s{1,100}\S+\s{1,100}({service}[^":]+)""",
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """for user \[({user}[^\]\s]+)""",
    """({failure_reason}Authentication Failed)"""
  ]
}
```