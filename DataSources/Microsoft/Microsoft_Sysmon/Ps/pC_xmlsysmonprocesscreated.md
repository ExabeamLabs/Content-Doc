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
  Conditions = [ """<Provider Name ='Microsoft-Windows-Sysmon'""", """<EventID>1</EventID>""", """<Channel>Microsoft-Windows-Sysmon/Operational</Channel>""", """<Data Name =""" ]
  Fields = [
    """<Data Name ='UtcTime'>({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)</Data>""",
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """<Computer>({host}[^<]{1,2000}?)</Computer>""",
    """<Data Name ='User'>((NT AUTHORITY|NT-AUTORITÄT|({domain}[^\\<]{1,2000}?))\\)?(SYSTEM|(NETWORK|LOCAL) SERVICE|({user}[^<]{1,2000}?))</Data>""",
    """<EventID>({event_code}\d{1,100})""",
    """<Security UserID='({user_sid}[^>]{1,2000}?)'/>""",
    """<Data Name ='LogonId'>({logon_id}[^<]{1,2000}?)</Data>""",
    """<Data Name ='Hashes'>[^=]{0,2000}?MD5=({md5}[A-F0-9a-f]{1,2000})[^<]{0,2000}?<\/Data>""",
    """<Data Name ='ProcessGuid'>\{({process_guid}[A-F0-9a-f-]{1,2000})\}</Data>""",
    """<Data Name ='ProcessId'>({pid}\d{1,100})</Data>""",
    """<Data Name ='ParentProcessGuid'>\{({parent_process_guid}[A-F0-9a-f-]{1,2000})\}</Data>""",
    """<Data Name ='CommandLine'>"?\s{0,100}({command_line}[^<]{1,2000}?)\s{0,100}</Data>""",
    """<Data Name ='Image'>(({directory}[^<]{1,2000})\\)?({process_name}[^<]{1,2000}?)</Data>""",
    """<Data Name ='Image'>({path}[^<]{1,2000}?)</Data>""",
    """<Data Name ='ParentImage'>({parent_process}(({parent_process_directory}[^<]{1,2000})\\)?({parent_process_name}[^<]{1,2000}?))<\/Data>"""
  ]
  DupFields = [ "host->dest_host","directory->process_directory","path->process" ]


}
```