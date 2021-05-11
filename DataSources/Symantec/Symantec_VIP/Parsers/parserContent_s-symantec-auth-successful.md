#### Parser Content
```Java
{
Name = s-symantec-auth-successful
  Vendor = Symantec
  Product = Symantec VIP
  Lms = Splunk
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS z"
  Conditions = [ """text=Authentication Success for user""", """StatusMessage: Success""" ]
  Fields = [ 
    """INFO.*?({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d\.\d\d\d \w+(\+|\-)\d{1,100})\s{0,100}"\s{1,100}\S+\s{1,100}({service}[^":]+)""",
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """for user \[({user}[^\]\s]+)"""
  ]
}
```