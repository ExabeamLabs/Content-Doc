#### Parser Content
```Java
{
Name = greenbay-4776
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4776"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """"event_id":"4776"""", """attempted to validate the credentials for an account""" ]
  Fields = [
    """({event_name}The computer attempted to validate the credentials for an account)""",
    """"time":"({time}\d+\/\d+\/\d\d\d\d \d+:\d\d:\d\d (am|AM|pm|PM))""",
    """"computer":"({host}[^"]+)""",
    """"computer":"(?!(?:[A-Fa-f:\d.]+))[^."]+\.({domain}[^"]+)""",
    """"source_workstation":"({dest_host}[^"]+)""",
    """"error_code":"({result_code}[^"]+)""",
    """"logon_account":"({user}[^"]+)""",
    """"event_id":"({event_code}\d+)""",
    """"The ({login_type}computer|domain)(\s\w+)? attempted to validate the credentials""",
  ]
}
```