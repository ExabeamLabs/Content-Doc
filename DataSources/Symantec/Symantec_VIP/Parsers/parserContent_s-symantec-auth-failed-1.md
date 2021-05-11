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
    """INFO.*?({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d\.\d\d\d \w+(\+|\-)\d{1,100})\s{0,100}"\s{1,100}\S+\s{1,100}({service}[^":]+)""",
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """for user \[({user}[^\]\s]+)""",
    """reason=[^;]*;\s{0,100}({failure_reason}[^"]*)"""
  ]
}
```