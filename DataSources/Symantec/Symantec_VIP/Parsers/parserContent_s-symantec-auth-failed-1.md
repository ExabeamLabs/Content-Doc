#### Parser Content
```Java
{
Name = s-symantec-auth-failed-1
  Vendor = Symantec
  Product = Symantec VIP
  Lms = Splunk
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS z"
  Conditions = [ """text=Sending Acces-Reject for user""" ]
  Fields = [ 
    """INFO.*?({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d\.\d\d\d \w+(\+|\-)\d+)\s*"\s+\S+\s+({service}[^":]+)""",
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """for user \[({user}[^\]\s]+)""",
    """reason=[^;]*;\s*({failure_reason}[^"]*)"""
  ]
}
```