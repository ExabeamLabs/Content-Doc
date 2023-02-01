#### Parser Content
```Java
{
Name = sap-app-login
  DataType = "app-login"
  Conditions = [ """CEF:""", """|SECUDE|C-Bus|""", """dvchost=""", """|AU1|Dialog Logon Successful|""" ]

sap-login-activity = {
  Vendor = SAP
  Product = SAP
  Lms = Syslog
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Fields = [
    """dvchost=({host}[^\s]{1,2000})""",
    """dvc=({host_ip}[a-fA-F\d:.]{1,2000})""",
    """end=({time}\w+\s\d{1,100}\s\d{1,100}\s\d\d:\d\d:\d\d)""",
    """SECUDE\|C-Bus\|[^\|]{1,2000}\|(|({activity_id}[^\|]{1,2000}))\|(|({event_name}[^\|]{1,2000}))\|""",
    """suser=({user}[^\s]{1,2000})\s\w+=""",
    """shost=(({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}))|({src_host}[^\s]{1,2000}))""",
    """cat=({category}[^=]{1,2000}?)(\s\w+=|\s{0,100}$)""",
    """requestClientApplication=({app}[^"]{1,2000}?)\s\w+=""",
    """msg=({additional_info}[^"]{1,2000}?)\s{1,100}\w+="""
  ]
  DupFields = [ "activity_id->event_code" 
}
```