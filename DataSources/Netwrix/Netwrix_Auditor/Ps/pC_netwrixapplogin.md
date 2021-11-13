#### Parser Content
```Java
{
Name = netwrix-app-login
  DataType = "app-login"
  Conditions = [ """CEF:0|Netwrix|""", """|Successful Logon|""" ]
  Fields = ${NetWrixParserTemplates.netwrix-app-activity-2.Fields}[
    """CEF:0\|Netwrix\|(AD FS|Logon Activity|Self-audit)\|[^\|]{1,2000}\|[^\|]{1,2000}\|({activity}[^\|]{1,2000})\|""",
  ]

netwrix-app-activity-2 = {
  Vendor = Netwrix
  Product = Netwrix Auditor
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """start=({time}\w{3} \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """suser=(N\/A|({user_email}[^@]{1,2000}@[^\\\s]{1,2000})|(({domain}[^\\\s]{1,2000})\\+)?({user}[^\\\s]{1,2000})) """,
    """shost=(unknown|({src_host}[^\s]{1,2000}))""",
    """({app}Netwrix)""",
    """msg=({additional_info}.+?)(\s\w+=|$)""",
  
}
```