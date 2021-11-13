#### Parser Content
```Java
{
Name = netwrix-ad-member-removed
  DataType = "member-removed"
  Conditions = [ """CEF:0|Netwrix|Active Directory|""", """|Modified group|""", """Removed: """ ]
  Fields = ${NetWrixParserTemplates.netwrix-app-activity-2.Fields}[
    """CEF:0\|Netwrix\|Active Directory\|[^\|]{1,2000}\|[^\|]{1,2000}\|({activity}[^\|]{1,2000})\|""",
    """cat=group.+?filePath=\\+?([^\\]{1,2000}\\+)*?({group_name}[^\\]{1,2000}) start=""",
    """Removed:.+?"{1,20}(\\+)?([^\\\/]{1,2000}[\\\/]{1,2000})*?({target_user}[^\\\/]{1,2000}?)(;|$|")""",
    """Group Type: "{1,20}({group_type}[^"]{1,2000})"{1,20}""",
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