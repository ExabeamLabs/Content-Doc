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
      """\scategoryOutcome=(|/({outcome}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
      """"(?:winlog\.)?computer_name\\*":\\*"({host}[^\\"]+)""",
      """@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """Type\s{0,100}=\s{0,100}"({outcome}[^";]+)"""",
      """Keywords=({outcome}.+?);?\s{0,100}(\w+=)""",
      """<Computer>({host}[^<]+)</Computer>""",
      """Computer(\w+)?["\s]*(:|=)\s{0,100}"?({host}[^\s";]+)""",
      """({event_code}4672)""",
      """Account Name(:|=)\s{0,100}(-|SYSTEM|({user}[^\s]+?))[\s;]*Account Domain(:|=)""",
      """Account Domain(:|=)\s{0,100}(-|({domain}[^\s]+?))[\s;]*Logon ID(:|=)""",
      """\s{0,100}Logon ID(:|=)\s{0,100}({logon_id}.+?)[\s;]*Privileges(:|=)\s{0,100}({privileges}.+?)(<|\s{0,100}User:|\s{1,100}\d{1,100}|,|\s{0,100}"|;|\s{0,100}$)"""
    ]
    DupFields = ["host->dest_host"]
  }
```