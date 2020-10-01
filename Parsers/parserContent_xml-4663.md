#### Parser Content
```Java
{
Name = xml-4663
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-4663"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<Data Name""", """"EventID":4663""", """xmlns""", """"Activity":"4663 - An attempt was made to access an object.""""  ]
  Fields = [ 
    """"TimeGenerated"+:"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"Computer"+:"+({host}[^"]+)""",
    """"EventID"+:({event_code}\d+)""",
    """<Data Name(\\)?=(\\)?"+SubjectUserSid(\\)?"+>(?:NONE_MAPPED|({user_sid}[^<]+))<\/Data>""",
    """<Data Name(\\)?=(\\)?"+SubjectUserName(\\)?"+>(LOCAL SERVICE|({user}[^<]+))<\/Data>""",
    """<Data Name(\\)?=(\\)?"+SubjectDomainName(\\)?"+>(NT AUTHORITY|({domain}[^<]+))<\/Data>""",
    """<Data Name(\\)?=(\\)?"+SubjectLogonId(\\)?"+>({logon_id}[^<]+)<\/Data>""",
    """<Data Name(\\)?=(\\)?"+ObjectType(\\)?"+>({file_type}[^<]+)<\/Data>""",
    """<Data Name(\\)?=(\\)?"+ObjectName(\\)?"+>({file_path}({file_parent}.+?)[\\\/]+({file_name}(?:[^<\\\/:]+?)(\.({file_ext}\w+))?)|[^\\:<]+)<\/Data>""", 
    """<Data Name(\\)?=(\\)?"+ProcessName(\\)?"+>({process}({directory}(?:[^<]+)?[\\\/])?({process_name}[^\\\/"<]+?))<\/Data>""",
    """<Data Name(\\)?=(\\)?"+AccessList(\\)?"+>({accesses}.+?)\s(\\t)*""",
    """AccessMask"+:"+({access_mask}[^"]+)""", 
  ]
  DupFields = [ "host->dest_host","directory->process_directory" ]
}
```