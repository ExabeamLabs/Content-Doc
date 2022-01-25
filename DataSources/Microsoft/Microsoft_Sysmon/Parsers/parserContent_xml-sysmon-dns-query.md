#### Parser Content
```Java
{
Name = xml-sysmon-dns-query
  Vendor = Microsoft
  Product = Microsoft Sysmon
  Lms = Splunk
  DataType = "dns-query"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
  Conditions = [ """<Provider Name='Microsoft-Windows-Sysmon'""", """<EventID>22</EventID>""", """<Channel>Microsoft-Windows-Sysmon/Operational</Channel>""", """<Data Name=""" ]
  Fields = [
    """<Data Name='UtcTime'>({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)</Data>""",
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """<EventID>({event_code}\d{1,100})</EventID>""",
    """<Computer>({host}.+?)</Computer>""",
    """<Security UserID='({user_sid}.+?)'/>""",
    """(?i)<Data Name='ProcessGuid'>\{({process_guid}[A-F0-9a-f-]{1,2000})\}</Data>""",
    """<Data Name='ProcessId'>({pid}\d{1,100})</Data>""",
    """<Data Name='QueryName'>({query}.+?)\s{0,100}</Data>""",
    """<Data Name='QueryResults'>({response}.+?)\s{0,100}</Data>""",
    """<Data Name='Image'>({path}(({directory}[^<]{0,2000})\\+)?({process_name}.+?))</Data>""",
  ]
   
}
```