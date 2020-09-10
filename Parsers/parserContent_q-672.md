#### Parser Content
```Java
{
Name = q-672
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = QRadar
  DataType = "windows-672"
  TimeFormat = "epoch_sec"
  Conditions = [ "EventIDCode=672" ]
  Fields = [
             """EventID=({event_code}\d+).+?Supplied Realm Name:\s+({domain}[^\s]+)""",
             """TimeGenerated=({time}\d+)""",
             """Computer=({host}[^\s]+)""",
	     """User Name:\s+({user}.+?)\s+Supplied Realm Name:.+?Result Code:\s+({result_code}.+?)\s.+Client Address:\s+({dest_ip}[a-fA-F:\d.]+)""" ]
}
```