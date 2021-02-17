#### Parser Content
```Java
{
Name = cef-egnyte-file-operations
  Vendor = Egnyte
  Product = Egnyte
  Lms = ArcSight
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """CEF:""", """|resource-acl-updated|""", """destinationServiceName=Egnyte""", """dproc=permissions-audit-report""", """ACL was""", """with permission""" ]
  Fields = [
    """"time":"({time}\d+-\d+-\d+T\d+:\d+:\d+Z)""",
    """"assigner":"[^"\(]+\(\s*({user_email}[^\s@\(\)]+@[^\s@\(\)]+)""",
    """"assignee":"({object}[^"]+)""",
    """"folder":"(|({file_path}({file_parent}[^"]*?)[\\\/]*({file_name}[^"\\\/]+[\\\/](\.({file_ext}[^\\\/\.\s"]+))?)))\s*"""",
    """({accesses}ACL was.*?with permission\s+\[[^\]]*\])""",
    """destinationServiceName=({service}[^"]+?)\s+(\w+=|$)""",
    """msg=({additional_info}[^"]+?)\s+(\w+=|$)""",
  ]
}
```