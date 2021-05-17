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
  Conditions = [ """<EventID>4663</EventID>""", """<Data Name"""]
  Fields = [ 
    """<TimeCreated SystemTime(\\)?='({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})"""
    """<Computer>([^<>]{1,2000}?[\\\/]{1,2000})?({host}[^<]{1,2000})</Computer>""",
    """<EventID>({event_code}[^<]{1,2000})</EventID>""",
    """<Data Name(\\)?=('|")SubjectUserSid('|")>(?:NONE_MAPPED|({user_sid}[^<]{1,2000}))<\/Data>""",
    """<Data Name(\\)?=('|")SubjectUserName('|")>(?=\w)({user}[^<]{1,2000})</Data>""",
    """<Data Name(\\)?=('|")SubjectDomainName('|")>(?=\w)({domain}[^<]{1,2000})</Data>""",
    """<Data Name(\\)?=('|")SubjectLogonId('|")>({logon_id}[^<]{1,2000})</Data>""",
    """<Data Name(\\)?=('|")ObjectType('|")>({file_type}[^<]{1,2000})</Data>""",
    """<Data Name(\\)?=('|")ObjectName('|")>({file_path}[^<]{1,2000})</Data>""",
    """<Data Name(\\)?=('|")ObjectName('|")>[^<]{1,2000}[\\\/]{1,2000}({file_name}(?:[^<\\\/:]{1,2000}?)(\.({file_ext}\w+))?|[^\\:<]{1,2000})</Data>""",
    """<Data Name(\\)?=('|")ObjectName('|")>({file_parent}.+?)[\\\/]{1,2000}(?:[^\\\/]{1,2000}?)</Data>""",
    """<Data Name(\\)?=('|")ProcessName('|")>({process}({directory}(?:[^<]{1,2000})?[\\\/])?({process_name}[^\\\/"<]{1,2000}?))</Data>""",
    """<Data Name(\\)?=('|")AccessList('|")>([^\d\w]{1,2000})?({accesses}[\d\w]{1,2000})""",
    """<Data Name(\\)?='AccessMask'>({access_mask}[^<]{1,2000})""",
  ]
  DupFields = [ "host->dest_host","directory->process_directory" ]
}
```