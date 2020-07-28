#### Parser Content
```Java
{
Name = q-quest-directory-access
  Vendor = Quest Software
  Product = Change Auditor
  Lms = QRadar
  DataType = "ds-access"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """LEEF:""", """|Quest Software""" , """|Change Auditor|""" , """action=""" ]
  Fields = [
    """devTime=({time}\w+\s+\d+\s+\d\d\d\d\s+\d\d:\d\d:\d\d)""",
    """ipAddress=({host_ip}[A-Fa-f:\d.]+)""",
    """computer=({host}[\w\-.]+)""",
    """dst=({dest_ip}[A-Fa-f:\d.]+)""",
    """dstPort=({dest_port}\d+)""",
    """event=({event_name}[^\^=]+?)\^""",
    """action=({activity_type}[^\^=]+?)\^""",
    """result=({outcome}[^\^=]+?)\^""",
    """user=(({domain}[^\\\s\^=]+)\\+)?({user}[^\\\s\^=]+)""",
    """domainFqdn=({domain}[^\s\^]+)""",
    """origin=(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[\w\-.]+))""",
    """originIPv4=({src_ip}[A-Fa-f:\d.]+)""",
    """objectClass=({object_class}[^\^]+)""",
    """objectName=({object}[^\^]+)""",
    """objectDn=({object_dn}[^\^]+)""",
    """objectDn=CN=[^\^]+?({object_ou}OU=[^\^]+)""",
    """attributeName=({attribute}[^\^]+)""",
    """adUsnChangedPre=({old_attribute}[^\^]+)""",
    """adUsnChangedPost=({new_attribute}[^\^]+)""",
  ]
}
```