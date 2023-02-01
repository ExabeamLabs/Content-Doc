#### Parser Content
```Java
{
Name = beyondtrust-app-activity-1
  Vendor = BeyondTrust
  Product = Secure Remote Access
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """|Bomgar|Privileged Access|""", """sessionId=""", """dstUser=""" ]
  Fields = [ 
    """({app}Privileged Access)""",
    """\|Privileged Access\|([^\|]{1,2000}\|){2}({activity}[^\|]{1,2000})\|""",
    """srcAddr=({src_ip}[a-fA-F\d:.]{1,2000})""",
    """srcPort=({src_port}\d{1,5})""",
    """srcHost=({src_host}[^\|]{1,2000})""",
    """\|dstUser=(\[Pinned\] )?(({user_fullname}({user_firstname}[^\s\|]{1,2000})\s({user_lastname}[^\|]{1,2000}))|({target_user}[^\|]{1,2000}))""",
    """\|srcUser=(\[Pinned\] )?(({user_fullname}({user_firstname}[^\s\|]{1,2000})\s({user_lastname}[^\|]{1,2000}))|({user_email}[^\s@\|]{1,2000}@[^\s@\|]{1,2000})|({user}[^\|]{1,2000}))""",
    """msg=({additional_info}[^\|]{1,2000}?)\s{0,100}\|""",
    """credentialName =({additional_info}[^\|]{1,2000})"""
  ]
  DupFields = [ "activity->event_name", "target_user->object" ]


}
```