#### Parser Content
```Java
{
Name = beyondtrust-privileged-access-1
  Vendor = BeyondTrust
  Product = BeyondTrust
  Lms = Direct
  DataType = "privileged-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [  """|BeyondTrust|Secure Remote Access|""", """|deviceHost=""", """|sessionId=""", """|externalKeyLabel=""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """sessionId=({session_id}[^\|]{1,2000})""",
    """deviceHost=({host}[^\|]{1,2000})""",
    """dstUser=({dest_user}[^\|]{1,2000})""",
    """srcUser=({src_user}[^\|]{1,2000})""",
    """srcUser=({user_email}[^@]{1,2000}@[^\.]{1,2000}\.[^\|]{1,2000})\|\w+=""",
    """sessionOwner=({user_fullname}[^\|]{1,2000})""",
    """\|BeyondTrust\|Secure Remote Access\|(?:[^\|]{1,2000}\|){2}({event_name}[^\|]{1,2000})\|""",
    """srcHost=({src_host}[^\|]{1,2000})""",
    """srcAddr=({src_ip}[a-fA-F0-9.:]{1,2000})\|""",
    """srcPort=({src_port}\d{1,100})""",
    """dstHost=({dest_host}[^\|]{1,2000})""",
    """dstAddr=({dest_ip}[a-fA-F0-9.:]{1,2000})\|""",
    """dstPort=({dest_port}\d{1,100})""",
    """confMemOs=({os}[^\|]{1,2000})""",
    """cmdShellViewUrl=({additional_info}[^\|]{1,2000})"""
  ]
  DupFields = ["dest_user->account"]
}
```