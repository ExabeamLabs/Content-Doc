#### Parser Content
```Java
{
Name = sysmon-windows-dns-query
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "dns-query"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """QueryName:""", """QueryResults:""", """ProcessGuid:""", """Image:""" ]
  Fields = [
    """UtcTime:\s*({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d\.\d\d\d)\s""",
    """exabeam_host=({host}[\w.\-]+)""",
    """QueryName:\s*({query}[^\s]+)""",
    """ProcessGuid:\s*\{({process_guid}[A-F0-9a-f-]+)\}""",
    """ProcessId:\s*({pid}\d+)""",
    """QueryResults:\s({response}.+?)\sImage:""",
    """Image:\s*(?:<unknown process>|({process}({directory}[^"]*[\\\/]+)?({process_name}[^"\\\/]+)))\s""",
	]
}
```