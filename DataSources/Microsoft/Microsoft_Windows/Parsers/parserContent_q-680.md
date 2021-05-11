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
             """EventID=({event_code}\d{1,100})""",
             """TimeGenerated=({time}\d{1,100})""",
             """Computer=({host}[^\s]+)""",
	     """Domain=({domain}[\w\-]+)\s{1,100}EventID=""",
             """Logon account:\s{0,100}({user}[^@]+?)(@[^\s]*)?\s{1,100}Source Workstation:\s{0,100}(\\+)?({dest_host}[^\s.]+).+?Error Code:\s{0,100}({result_code}[^\s]+)""",
             """Computer=[^\s.]+(\.({domain}[^\s.]+)[^\s]*)?"""]
}
```