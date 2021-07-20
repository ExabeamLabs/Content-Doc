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
    """"time":"({time}\d{1,100}\/\d{1,100}\/\d\d\d\d \d{1,100}:\d\d:\d\d (am|AM|pm|PM))""",
    """"computer":"({host}[^"]{1,2000})""",
    """"computer":"(?!(?:[A-Fa-f:\d.]{1,2000}))[^."]{1,2000}\.({domain}[^"]{1,2000})""",
    """"source_workstation":"({dest_host}[^"]{1,2000})""",
    """"error_code":"({result_code}[^"]{1,2000})""",
    """"logon_account":"({user}[^"]{1,2000})""",
    """"event_id":"({event_code}\d{1,100})""",
    """"The ({login_type}computer|domain)(\s\w+)? attempted to validate the credentials""",
  ]
}
```