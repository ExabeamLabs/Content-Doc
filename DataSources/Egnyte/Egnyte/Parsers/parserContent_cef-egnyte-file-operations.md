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
    """"time":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}Z)""",
    """"assigner":"[^"\(]+\(\s{0,100}({user_email}[^\s@\(\)]+@[^\s@\(\)]+)""",
    """"assignee":"({object}[^"]+)""",
    """"folder":"(|({file_path}({file_parent}[^"]*?)[\\\/]*({file_name}[^"\\\/]+[\\\/](\.({file_ext}[^\\\/\.\s"]+))?)))\s{0,100}"""",
    """({accesses}ACL was.*?with permission\s{1,100}\[[^\]]*\])""",
    """destinationServiceName=({service}[^"]+?)\s{1,100}(\w+=|$)""",
    """msg=({additional_info}[^"]+?)\s{1,100}(\w+=|$)""",
  ]
}
```