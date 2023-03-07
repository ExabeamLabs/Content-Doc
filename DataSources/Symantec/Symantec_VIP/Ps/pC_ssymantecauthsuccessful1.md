#### Parser Content
```Java
{
Name = s-symantec-auth-successful-1
  Vendor = Symantec
  Product = Symantec VIP
  Lms = Splunk
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS z"
  Conditions = [ """text=Authentication Success for user""", """StatusMessage: Mobile push request approved by user""" ]
  Fields = [
    """INFO[^~]{1,2000}({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d\.\d\d\d \w+(\+|\-)\d{1,100})\s{0,100}"\s{1,100}\S{1,2000}\s{1,100}({service}[^":]{1,2000})""",
    """({event_name}Authentication Success for user)"""
    """for user \[(({domain}[^\\]{1,2000})\\)?({user}[^\]\s]{1,2000})"""
  ]


}
```