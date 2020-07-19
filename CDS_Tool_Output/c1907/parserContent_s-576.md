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
    """\sEventCode=({event_code}\d+)""",
    """\sType=({outcome}.+?)(\s+\w+=|\s*$)""",
    """\sComputerName=({host}.+?)(\s+\w+=|\s*$)""",
    """\sUser=({user}.+?)(\s+\w+=|\s*$)""",
    """\sSid=({user_sid}.+?)(\s+\w+=|\s*$)""",
    """\s*Domain:\s*(?:-|({domain}.*?))\s*Logon ID:\s*\(?({logon_id}[^)]*)\)?\s*Privileges:\s*({privileges}.*?)\s*$"""
  ]
  DupFields = ["host->dest_host"]
}

{
  Name = exalms-680
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-680"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"event_id":680""", """"Logon attempt by:""", """"@timestamp"""" ]
  Fields = [
    """({event_name}Logon attempt)""",
    """"@timestamp"\s*:\s*"({time}[^"]+)"""",
    """"computer_name"\s*:\s*"({host}[\w\-\.]+)"""",
    """"event_data"\s*:\s*\{.*?"(param3|SourceWorkstation)"\s*:\s*"({dest_host}[^"]+)"""",
    """"event_data"\s*:\s*\{.*?"(param4|ErrorCode)"\s*:\s*"({result_code}[^"]+)"""",
    """"event_data"\s*:\s*\{.*?"(param2|UserName|User)"\s*:\s*"({user}[^"]+)"""",
    """"hostname":"({domain}[^"]+)"""",
    """"user"\s*:\s*\{.*?"identifier"\s*:\s*"({user_sid}[^"]+)"""",
    """"user"\s*:\s*\{.*?"domain":"({domain}[^"]+)"""",
    """"user"\s*:\s*\{.*?"name":"({user}[^"]+)"""",
    """"event_id"\s*:\s*({event_code}\d+)""",
    """"record_number"\s*:\s*"({record_id}\d+)""",
  ]
}
```