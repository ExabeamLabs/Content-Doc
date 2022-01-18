#### Parser Content
```Java
{
Name = azure-mfa-admin-activity
  Vendor = Microsoft
  Product = Microsoft Azure MFA
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """pfsvc: User""", """ changed user """, """ value """ ]
  Fields = [
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}.\d{1,100}:\d{1,100}),({host}[^\s,]{1,2000}),"pfsvc: User""",
    ""","pfsvc: User\s{1,100}"{1,20}(({user_email}[^"@]{1,2000}@[^"]{1,2000})|(({domain}[^\\\s]{1,2000})\\+)?({user}[^\s"]{1,2000}))""",
    """changed user "{1,20}({target}[^"]{1,2000})"{1,20}\s{1,100}({additional_info}value\s{1,100}({activity}[^=]{1,2000}?)\s{1,100}from[^\.]{1,2000})\.""",
    """changed user "{1,20}({target}[^"]{1,2000})"{1,20}\s{1,100}({additional_info}value\s{1,100}({activity}[^=]{1,2000}?)\s{1,100}from "{1,20}[^"]{1,2000}"{1,20} to "{1,20}[^"]{1,2000}"{1,20})\."""
    ]


}
```