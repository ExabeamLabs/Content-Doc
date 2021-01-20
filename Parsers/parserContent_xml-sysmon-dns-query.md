#### Parser Content
```Java
{
Name = xml-sysmon-dns-query
  Vendor = Microsoft
  Product = Sysmon
  Lms = Splunk
  DataType = "dns-query"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
  Conditions = [ """<Provider Name='Microsoft-Windows-Sysmon'""", """<EventID>22</EventID>""", """<Channel>Microsoft-Windows-Sysmon/Operational</Channel>""", """<Data Name=""" ]
  Fields = [
    """<Data Name='UtcTime'>({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)</Data>""",
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
    """<EventID>({event_code}\d+)</EventID>""",
    """<Computer>({host}.+?)</Computer>""",
    """<Security UserID='({user_sid}.+?)'/>""",
    """(?i)<Data Name='ProcessGuid'>\{({process_guid}[A-F0-9a-f-]+)\}</Data>""",
    """<Data Name='ProcessId'>({pid}\d+)</Data>""",
    """<Data Name='QueryName'>({query}.+?)\s*</Data>""",
    """<Data Name='QueryResults'>({response}.+?)\s*</Data>""",
    """<Data Name='Image'>({path}(({directory}[^<]*)\\+)?({process_name}.+?))</Data>""",
  ]
   
}
```