#### Parser Content
```Java
{
Name = cef-member-removed-2008
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-member-removed"
  TimeFormat = "epoch"
  Conditions = [ """|IntersectAlliance|Snare|""", """4733|A member was removed from a security-enabled""" ]
  Fields = [
    """({event_name}A member was removed from a security-enabled [\w\s]+ group)""",
    """(\||\s)rt=({time}\d+)""",
    """(\||\s)dvchost=({host}[\w\-.]+)\s*(\w+=|$)""",
    """(\||\s)dhost=({dest_host}[\w\-.]+)\s*(\w+=|$)""",
    """(\||\s)dst=({dest_ip}[a-fA-F:\d.]+)\s*(\w+=|$)""",
    """(\||\s)Microsoft-Windows-Security-Auditing:\s*({event_code}\d+)""",
    """(\||\s)A member was removed from a security-enabled\s*({group_type}[^\s]+)\s+group""",
    """(\||\s)suser=(({domain}[^\\\s]+)\\+)?({user}[^\\\s]+)\s*(\w+=|$)""",
    """(\||\s)sntdom=({domain}.+?)\s*(\w+=|$)""",
    """(\||\s)suid=({logon_id}[^\s]+)\s*(\w+=|$)""",
    """(\||\s)duser=({account_id}(?=[^\\]+\\)({sid_domain}[^\\]+?)\\({sid_user}[^\\]+?)|(?:.+?))\s*(\w+=|$)""",
    """(\||\s)duid=\s*(-|({account_dn}CN=.+?({account_ou}OU.+?DC=[\w\-]+)))\s*dpriv=""",
    """(\||\s)ad\.Group:Security_,ID=({group_id}[^\s]+)\s*(\w+=|$)""",
    """(\||\s)cs6=(({group_domain}[^\\]+?)\\+)?({group_name}[^\\]+?)\s*(\w+=|$)""",
  ]
}
```