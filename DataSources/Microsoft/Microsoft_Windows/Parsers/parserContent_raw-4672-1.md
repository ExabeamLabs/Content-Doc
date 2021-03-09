#### Parser Content
```Java
{
Name = raw-4672-1
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-privileged-access"
    TimeFormat = "yyyy-MM-DD'T'HH:mm:ss"
    Conditions = ["Special privileges assigned to new logon", "Privileges", "computer_name"]
    Fields = [
      """({event_name}Special privileges assigned to new logon)""",
      """\scategoryOutcome=(|/({outcome}.+?))(\s+\w+=|\s*$)""",
      """"(?:winlog\.)?computer_name\\*":\\*"({host}[^\\"]+)""",
      """@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """Type\s*=\s*"({outcome}[^";]+)"""",
      """Keywords=({outcome}.+?);?\s*(\w+=)""",
      """<Computer>({host}[^<]+)</Computer>""",
      """Computer(\w+)?["\s]*(:|=)\s*"?({host}[^\s";]+)""",
      """({event_code}4672)""",
      """Account Name(:|=)\s*(-|SYSTEM|({user}[^\s]+?))[\s;]*Account Domain(:|=)""",
      """Account Domain(:|=)\s*(-|({domain}[^\s]+?))[\s;]*Logon ID(:|=)""",
      """\s*Logon ID(:|=)\s*({logon_id}.+?)[\s;]*Privileges(:|=)\s*({privileges}.+?)(<|\s*User:|\s+\d+|,|\s*"|;|\s*$)"""
    ]
    DupFields = ["host->dest_host"]
  }
```