#### Parser Content
```Java
{
Name = netwrix-ad-ds-access
  DataType = "ds-access"
  Conditions = [ """CEF:0|Netwrix|Active Directory|""" ]
  Fields = ${NetWrixParserTemplates.netwrix-app-activity-2.Fields}[
    """CEF:0\|Netwrix\|Active Directory\|[^\|]{1,2000}\|[^\|]{1,2000}\|({activity}[^\|]{1,2000})\|""",
    """cat=({object_class}[^\s]{1,2000}).+?filePath=({object_dn}[^\s]{1,2000}\\({object}[^\s]{1,2000}?)) start=""",
    """cat=computer.+?filePath=[^\s]{1,2000}\\({computer_name}[^\s]{1,2000}?) start=""",
    """cat=user.+?filePath=[^\s]{1,2000}\\({target_user}[^\s]{1,2000}?) start=""",
    """cat=group.+?filePath=\\+?([^\\]{1,2000}\\+)*?({target_group}[^\\]{1,2000}) start=""",
    """msg=Object Path changed from "{1,20}({old_value}[^"]{1,2000})"{1,20} to "{1,20}({new_value}[^"]{1,2000})"{1,20}""",
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