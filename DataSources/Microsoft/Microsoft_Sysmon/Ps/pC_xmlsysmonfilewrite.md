#### Parser Content
```Java
{
Name = xml-sysmon-file-write
  DataType = "file-operations"
  IsHVF = true
  Conditions = [ """<EventID>13</EventID>""", """<Provider Name ='Microsoft-Windows-Sysmon'""" ]
  Fields = ${MicrosoftParserTemplates.xml-sysmon-activity.Fields}[
    """<Data Name ='TargetObject'>({file_path}(({file_parent}[^<>]{1,2000}?)[\\\/]{1,2000})?({file_name}[^\\\/<>]{0,2000}?(\.({file_ext}\w+))?))<\/Data>""",
  ]
  DupFields = [ "host->dest_host" ]

xml-sysmon-activity = {
  Vendor = Microsoft
  Product = Microsoft Sysmon
  Lms = Direct
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Fields = [
    """<Provider Name ='Microsoft-Windows-Sysmon' Guid='\{({process_guid}[^}]{1,2000}?)\}""",
    """<Data Name ='UtcTime'>({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100})""",
    """<EventID>({event_code}\d{1,100})</EventID>""",
    """<Task>({activity}.*?)</Task>""",
    """<Execution ProcessID='({pid}\d{1,100})""",
    """<Computer>({host}.+?)</Computer>""",
    """<Security UserID='({user_sid}[^']{1,2000})'""",
    """<Data Name ='Image'>({process}(({directory}[^<>]{1,2000}?)[\\\/]{1,2000})?({process_name}[^\\\/<>]{1,2000}?))<\/Data>""",
    """<Data Name ='TargetFilename'>({file_path}(({file_parent}[^<>]{1,2000}?)[\\\/]{1,2000})?\s{0,100}({file_name}[^\\\/<>]{0,2000}?(\.({file_ext}\w+))?))<\/Data>""",
    """<Keywords>({outcome}.+?)<\/Keywords>""",
    """<Data Name ='ProcessGuid'>\{({process_guid}.+?)\}<\/Data>""",
    """<Data Name ='ProcessId'>({pid}\d{1,100})""",
  
}
```