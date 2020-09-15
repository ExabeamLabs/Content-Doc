#### Parser Content
```Java
{
Name = s-xml-4663
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-4663"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "<EventID>4663</EventID>", "<Data Name="]
  Fields = [ """SystemTime=('|")({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>([^<>]+?[\\\/]+)?({host}[^<]+)</Computer>""",
    """<EventID>({event_code}[^<]+)</EventID>""",
    """<Data Name=('|")SubjectUserSid('|")>(?:NONE_MAPPED|({user_sid}[^<]+))</Data>""",
    """<Data Name=('|")SubjectUserName('|")>(?=\w)({user}[^<]+)</Data>""",
    """<Data Name=('|")SubjectDomainName('|")>(?=\w)({domain}[^<]+)</Data>""",
    """<Data Name=('|")SubjectLogonId('|")>({logon_id}[^<]+)</Data>""",
    """<Data Name=('|")ObjectType('|")>({file_type}[^<]+)</Data>""",
    """<Data Name=('|")ObjectName('|")>({file_path}[^<]+)</Data>""",
    """<Data Name=('|")ObjectName('|")>[^<]+[\\\/]+({file_name}(?:[^<\\\/:]+?)(\.({file_ext}\w+))?|[^\\:<]+)</Data>""",
    """<Data Name=('|")ObjectName('|")>({file_parent}.+?)[\\\/]+(?:[^\\\/]+?)</Data>""",
    """<Data Name=('|")ProcessName('|")>({process}({directory}(?:[^<]+)?[\\\/])?({process_name}[^\\\/"<]+?))</Data>""",
    """<Data Name=('|")AccessList('|")>({accesses}[^<]+?)\s*</Data>""",
    """Access Request Information:\s*Accesses:\s*({accesses}.+?)\s+Access Mask:\s*({access_mask}\w+)?""",
  ]
  DupFields = [ "host->dest_host","directory->process_directory" ]
}
```