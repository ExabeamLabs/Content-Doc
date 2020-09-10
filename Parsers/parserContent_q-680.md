#### Parser Content
```Java
{
Name = q-680
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = QRadar
  DataType = "windows-680"
  TimeFormat = "epoch_sec"
  Conditions = [ "EventIDCode=680" ]
  Fields = [
    """({event_name}Logon attempt)""",
             """EventID=({event_code}\d+)""",
             """TimeGenerated=({time}\d+)""",
             """Computer=({host}[^\s]+)""",
	     """Domain=({domain}[\w\-]+)\s+EventID=""",
             """Logon account:\s*({user}[^@]+?)(@[^\s]*)?\s+Source Workstation:\s*(\\+)?({dest_host}[^\s.]+).+?Error Code:\s*({result_code}[^\s]+)""",
             """Computer=[^\s.]+(\.({domain}[^\s.]+)[^\s]*)?"""]
}
```