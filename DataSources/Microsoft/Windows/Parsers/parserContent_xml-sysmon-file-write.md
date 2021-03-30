#### Parser Content
```Java
{
Name = xml-sysmon-file-write
  DataType = "file-operations"
  IsHVF = true
  Conditions = [ """<EventID>13</EventID>""", """<Provider Name='Microsoft-Windows-Sysmon'""" ]
  Fields = ${MicrosoftParserTemplates.xml-sysmon-activity.Fields}[
    """<Data Name='TargetObject'>({file_path}(({file_parent}[^<>]+?)[\\\/]+)?({file_name}[^\\\/<>]*?(\.({file_ext}\w+))?))<\/Data>""",
  ]
  DupFields = [ "host->dest_host" ]
}
xml-sysmon-activity = {
  Vendor = Microsoft
  Product = Sysmon
  Lms = Direct
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Fields = [
    """<Provider Name='Microsoft-Windows-Sysmon' Guid='\{({process_guid}[^}]+?)\}""",
    """<Data Name='UtcTime'>({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)""",
    """<EventID>({event_code}\d+)</EventID>""",
    """<Task>({activity}.*?)</Task>""",
    """<Execution ProcessID='({pid}\d+)""",
    """<Computer>({host}.+?)</Computer>""",
    """<Security UserID='({user_sid}[^']+)'""",
    """<Data Name='Image'>({process}(({directory}[^<>]+?)[\\\/]+)?({process_name}[^\\\/<>]+?))<\/Data>""",
    """<Data Name='TargetFilename'>({file_path}(({file_parent}[^<>]+?)[\\\/]+)?\s*({file_name}[^\\\/<>]*?(\.({file_ext}\w+))?))<\/Data>""",
    """<Keywords>({outcome}.+?)<\/Keywords>""",
    """<Data Name='ProcessGuid'>\{({process_guid}.+?)\}<\/Data>""",
    """<Data Name='ProcessId'>({pid}\d+)""",
  ]

```