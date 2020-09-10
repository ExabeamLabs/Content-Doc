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
    """INFO.*?({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d\.\d\d\d \w+(\+|\-)\d+)\s*"\s+\S+\s+({service}[^":]+)""",
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """for user \[({user}[^\]\s]+)""",
    """({failure_reason}Authentication Failed)"""
  ]
}
```