#### Parser Content
```Java
{
Name = xml-sysmon-process-created
  Vendor = Microsoft
  Product = Microsoft Sysmon
  Lms = Splunk
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
  Conditions = [ """<Provider Name='Microsoft-Windows-Sysmon'""", """<EventID>1</EventID>""", """<Channel>Microsoft-Windows-Sysmon/Operational</Channel>""", """<Data Name=""" ]
  Fields = [
    """<Data Name='UtcTime'>({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)</Data>""",
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
    """<Computer>({host}[^<]+?)</Computer>""",
    """<Data Name='User'>((NT AUTHORITY|NT-AUTORITÄT|({domain}[^\\<]+?))\\)?(SYSTEM|(NETWORK|LOCAL) SERVICE|({user}[^<]+?))</Data>""",
    """<EventID>({event_code}\d+)""",
    """<Security UserID='({user_sid}[^>]+?)'/>""",
    """<Data Name='LogonId'>({logon_id}[^<]+?)</Data>""",
    """<Data Name='Hashes'>[^=]*?MD5=({md5}[A-F0-9a-f]+)[^<]*?<\/Data>""",
    """<Data Name='ProcessGuid'>\{({process_guid}[A-F0-9a-f-]+)\}</Data>""",
    """<Data Name='ProcessId'>({pid}\d+)</Data>""",
    """<Data Name='ParentProcessGuid'>\{({parent_process_guid}[A-F0-9a-f-]+)\}</Data>""",
    """<Data Name='CommandLine'>"?\s*({command_line}[^<]+?)\s*</Data>""",
    """<Data Name='Image'>(({directory}[^<]+)\\)?({process_name}[^<]+?)</Data>""",
    """<Data Name='Image'>({path}[^<]+?)</Data>""",
    """<Data Name='ParentImage'>({parent_process}(({parent_process_directory}[^<]+)\\)?({parent_process_name}[^<]+?))<\/Data>"""
  ]
  DupFields = [ "host->dest_host","directory->process_directory","path->process" ]
}
```