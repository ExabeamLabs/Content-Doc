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
    """({event_name}A member was removed from a security-enabled [\w\s]{1,2000} group)""",
    """(\||\s)rt=({time}\d{1,100})""",
    """(\||\s)dvchost=({host}[\w\-.]{1,2000})\s{0,100}(\w+=|$)""",
    """(\||\s)dhost=({dest_host}[\w\-.]{1,2000})\s{0,100}(\w+=|$)""",
    """(\||\s)dst=({dest_ip}[a-fA-F:\d.]{1,2000})\s{0,100}(\w+=|$)""",
    """(\||\s)Microsoft-Windows-Security-Auditing:\s{0,100}({event_code}\d{1,100})""",
    """(\||\s)A member was removed from a security-enabled\s{0,100}({group_type}[^\s]{1,2000})\s{1,100}group""",
    """(\||\s)suser=(({domain}[^\\\s]{1,2000})\\+)?({user}[^\\\s]{1,2000})\s{0,100}(\w+=|$)""",
    """(\||\s)sntdom=({domain}.+?)\s{0,100}(\w+=|$)""",
    """(\||\s)suid=({logon_id}[^\s]{1,2000})\s{0,100}(\w+=|$)""",
    """(\||\s)duser=({account_id}(?=[^\\]{1,2000}\\)({sid_domain}[^\\]{1,2000}?)\\({sid_user}[^\\]{1,2000}?)|(?:.+?))\s{0,100}(\w+=|$)""",
    """(\||\s)duid=\s{0,100}(-|({account_dn}CN=.+?({account_ou}OU.+?DC=[\w\-]{1,2000})))\s{0,100}dpriv=""",
    """(\||\s)ad\.Group:Security_,ID=({group_id}[^\s]{1,2000})\s{0,100}(\w+=|$)""",
    """(\||\s)cs6=(({group_domain}[^\\]{1,2000}?)\\+)?({group_name}[^\\]{1,2000}?)\s{0,100}(\w+=|$)""",
  ]


}
```