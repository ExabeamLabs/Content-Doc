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
    """(\||\s)rt=({time}\d{1,100})""",
    """(\||\s)dvchost=({host}[\w\-.]+)\s{0,100}(\w+=|$)""",
    """(\||\s)dhost=({dest_host}[\w\-.]+)\s{0,100}(\w+=|$)""",
    """(\||\s)dst=({dest_ip}[a-fA-F:\d.]+)\s{0,100}(\w+=|$)""",
    """(\||\s)Microsoft-Windows-Security-Auditing:\s{0,100}({event_code}\d{1,100})""",
    """(\||\s)A member was removed from a security-enabled\s{0,100}({group_type}[^\s]+)\s{1,100}group""",
    """(\||\s)suser=(({domain}[^\\\s]+)\\+)?({user}[^\\\s]+)\s{0,100}(\w+=|$)""",
    """(\||\s)sntdom=({domain}.+?)\s{0,100}(\w+=|$)""",
    """(\||\s)suid=({logon_id}[^\s]+)\s{0,100}(\w+=|$)""",
    """(\||\s)duser=({account_id}(?=[^\\]+\\)({sid_domain}[^\\]+?)\\({sid_user}[^\\]+?)|(?:.+?))\s{0,100}(\w+=|$)""",
    """(\||\s)duid=\s{0,100}(-|({account_dn}CN=.+?({account_ou}OU.+?DC=[\w\-]+)))\s{0,100}dpriv=""",
    """(\||\s)ad\.Group:Security_,ID=({group_id}[^\s]+)\s{0,100}(\w+=|$)""",
    """(\||\s)cs6=(({group_domain}[^\\]+?)\\+)?({group_name}[^\\]+?)\s{0,100}(\w+=|$)""",
  ]
}
```