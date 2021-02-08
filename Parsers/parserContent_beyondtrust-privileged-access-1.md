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
    """sessionId=({session_id}[^\|]+)""",
    """deviceHost=({host}[^\|]+)""",
    """dstUser=(({user_email}[^@]+@[^\.]+\.[^\|]+)|({user}[^\|]+))""",
    """srcUser=({user_email}[^@]+@[^\.]+\.[^\|]+)\|\w+=""",
    """sessionOwner=({user_fullname}[^\|]+)""",
    """\|BeyondTrust\|Secure Remote Access\|(?:[^\|]+\|){2}({event_name}[^\|]+)\|""",
    """srcHost=({src_host}[^\|]+)""",
    """srcAddr=({src_ip}[a-fA-F0-9.:]+)\|""",
    """srcPort=({src_port}\d+)""",
    """dstHost=({dest_host}[^\|]+)""",
    """dstAddr=({dest_ip}[a-fA-F0-9.:]+)\|""",
    """dstPort=({dest_port}\d+)""",
    """confMemOs=({os}[^\|]+)""",
    """cmdShellViewUrl=({additional_info}[^\|]+)"""
  ]
}
```