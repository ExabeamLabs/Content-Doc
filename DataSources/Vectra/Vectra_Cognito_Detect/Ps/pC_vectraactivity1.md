#### Parser Content
```Java
{
Name = vectra-activity-1
  Product = Vectra Cognito Detect
  Vendor = Vectra
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """vectra_timestamp""","""reason""","""action""","""src_name"""]
  Fields =[
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})""",
    """({app}vectra)""",
    """"{0,20}dvchost"{0,20}:\s{0,100}"{1,20}({host}[^"]{1,2000})""",
    """"{0,20}src_name"{0,20}:\s{0,100}"{1,20}({src_host}[^"]{1,2000})""",
    """"{0,20}dest_name"{0,20}:\s{0,100}"{1,20}({dest_host}[^"]{1,2000})""",
    """"{0,20}src_ip"{0,20}:\s{0,100}"{1,20}({src_ip}[^"]{1,2000})""",
    """"{0,20}action"{0,20}:\s{0,100}"{1,20}({activity}[^"]{1,2000})""",
    """"{0,20}dest_ip"{0,20}:\s{0,100}"{1,20}({dest_ip}[^"]{1,2000})""",
    """"{0,20}reason"{0,20}:\s{0,100}"{1,20}({result}[^"]{1,2000})"""
  ]
 }
```