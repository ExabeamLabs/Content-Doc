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
    """INFO.*?({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d\.\d\d\d \w+(\+|\-)\d{1,100})\s{0,100}"\s{1,100}\S+\s{1,100}({service}[^":]{1,2000})""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """for user \[({user}[^\]\s]{1,2000})""",
    """reason=[^;]{0,2000};\s{0,100}({failure_reason}[^"]{0,2000})"""
  ]
}
```