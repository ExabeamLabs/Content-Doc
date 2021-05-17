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
    """devTime=({time}\w+\s{1,100}\d{1,100}\s{1,100}\d\d\d\d\s{1,100}\d\d:\d\d:\d\d)""",
    """ipAddress=({host_ip}[A-Fa-f:\d.]{1,2000})""",
    """computer=({host}[\w\-.]{1,2000})""",
    """dst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """dstPort=({dest_port}\d{1,100})""",
    """event=({event_name}[^\^=]{1,2000}?)\^""",
    """action=({activity_type}[^\^=]{1,2000}?)\^""",
    """result=({outcome}[^\^=]{1,2000}?)\^""",
    """user=(({domain}[^\\\s\^=]{1,2000})\\+)?({user}[^\\\s\^=]{1,2000})""",
    """domainFqdn=({domain}[^\s\^]{1,2000})""",
    """origin=(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[\w\-.]{1,2000}))""",
    """originIPv4=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """objectClass=({object_class}[^\^]{1,2000})""",
    """objectName=({object}[^\^]{1,2000})""",
    """objectDn=({object_dn}[^\^]{1,2000})""",
    """objectDn=CN=[^\^]{1,2000}?({object_ou}OU=[^\^]{1,2000})""",
    """attributeName=({attribute}[^\^]{1,2000})""",
    """adUsnChangedPre=({old_attribute}[^\^]{1,2000})""",
    """adUsnChangedPost=({new_attribute}[^\^]{1,2000})""",
  ]
}
```