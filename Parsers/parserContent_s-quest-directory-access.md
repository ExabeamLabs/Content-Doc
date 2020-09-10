#### Parser Content
```Java
{
Name = s-quest-directory-access
  Vendor = Quest Software
  Product = Change Auditor
  Lms = Splunk
  DataType = "ds-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Quest Software|ChangeAuditor""" , """art""" , """deviceSeverity""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """dvc=({host}\S+)\.\s*(\w+=|$)""",
    """dvchost=({host}\S+)\s*(\w+=|$)""",
    """change for ({object_class}user|group)""",
    """sntdom=({domain}\S+)\s(\w+=|$)""",
    """categoryOutcome=({outcome}[^\s]*)\s""",
    """src=({src_ip}[^\s]+)\s*(\w+=|$)""",
    """\|({action}[^\|]*)\|(Low|Medium|High)""",
    """suser=({user_lastname}[^,]+),\s({user_firstname}([A-Za-z]+){1}(\s\w){0,1})\s""",
    """dpriv=({attribute}.+?)\s(\w+=|$)""",
    """cs1=({old_attribute}.+?)\s(\w+=|$)""",
    """cs2=({new_attribute}.+?)\s*(\w+=|$)""",
    """changed for user ({object_dn}.+?)\.\s(\w+=|$)""",
    """shost=({src_host}\S+)\s*(\w+=|$)""",
    """duser=({object}.+?)\s*(\w+=|$)"""
    """CN\\=.+?({object_ou}OU\\=.+?).\s*\w+=""",
  ]
}

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