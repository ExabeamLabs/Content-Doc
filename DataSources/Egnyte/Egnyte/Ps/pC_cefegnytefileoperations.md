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
  Conditions = [ """CEF:""", """|resource-acl-updated|""", """destinationServiceName =Egnyte""", """dproc=permissions-audit-report""", """ACL was""", """with permission""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"time":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}Z)""",
    """"assigner":"[^"\(]{1,2000}\(\s{0,100}({user_email}[^@\(\)]{1,2000}@[^\.\s@\(\)]{1,2000}\.[^"\)]{1,2000}?)\s{0,100}\)?"""",
    """"assignee":"({object}[^"]{1,2000})""",
    """"folder":"({file_path}({file_parent}[^"]{0,2000}?[\\\/]{1,2000})({file_name}[^"\\\/]{1,2000}?(\.({file_ext}[^"\.\\\/]{1,2000}))?)?)\s{0,100}"""",
    """({accesses}ACL was.*?with permission\s{1,100}\[[^\]]{0,2000}\])""",
    """destinationServiceName =({service}[^"]{1,2000}?)\s{1,100}(\w+=|$)""",
    """msg=({additional_info}[^"]{1,2000}?)\s{1,100}(\w+=|$)""",
    """({app}Egnyte)"""
  ]


}
```