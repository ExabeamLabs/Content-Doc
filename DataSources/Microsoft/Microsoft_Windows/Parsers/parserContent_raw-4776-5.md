#### Parser Content
```Java
{
Name = raw-4776-5
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4776"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """Microsoft-Windows-Security-Auditing""", """Credential Validation""", """4776""", """TargetUserName:""", """PackageName:""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\.\d{1,3}[+\-]{1,20}\d\d:\d\d""",
    """({host}[^\s]{1,2000})\s{1,100}Credential Validation""",
    """({event_code}4776)""",
    """TargetUserName:(({user_email}[^@,]{1,2000}@[^,]{1,2000})|({user}[^,]{1,2000})),\s{1,100}\w{1,2000}""",
    """Workstation:(({dest_ip}[a-fA-F\d:.]{1,2000}?):\d{1,100}|({dest_host}[^,]{1,2000})),""",
    """PackageName:({auth_package}[^,]{1,2000}?),""",    
    """Status:({result_code}[^,]{1,2000}),"""
  ]
}
```