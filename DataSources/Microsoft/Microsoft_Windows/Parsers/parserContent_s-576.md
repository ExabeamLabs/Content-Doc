#### Parser Content
```Java
{
Name = s-576
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-privileged-access"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """EventCode=576""", """Special privileges assigned to new logon""" ]
  Fields = [
    """({event_name}Special privileges assigned to new logon)""",
    """({time}\d\d/\d\d/\d\d\d\d \d\d:\d\d:\d\d (am|AM|pm|PM))""",
    """\sEventCode=({event_code}\d{1,100})""",
    """\sType=({outcome}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sComputerName=({host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sUser=({user}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sSid=({user_sid}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\s{0,100}Domain:\s{0,100}(?:-|({domain}.*?))\s{0,100}Logon ID:\s{0,100}\(?({logon_id}[^)]*)\)?\s{0,100}Privileges:\s{0,100}({privileges}.*?)\s{0,100}$"""
  ]
  DupFields = ["host->dest_host"]
}
```