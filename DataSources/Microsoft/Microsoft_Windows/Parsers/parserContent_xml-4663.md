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
    """"TimeGenerated"{1,20}:"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"Computer"{1,20}:"{1,20}({host}[^"]+)""",
    """"EventID"{1,20}:({event_code}\d{1,100})""",
    """<Data Name(\\)?=(\\)?"{1,20}SubjectUserSid(\\)?"{1,20}>(?:NONE_MAPPED|({user_sid}[^<]+))<\/Data>""",
    """<Data Name(\\)?=(\\)?"{1,20}SubjectUserName(\\)?"{1,20}>(LOCAL SERVICE|({user}[^<]+))<\/Data>""",
    """<Data Name(\\)?=(\\)?"{1,20}SubjectDomainName(\\)?"{1,20}>(NT AUTHORITY|({domain}[^<]+))<\/Data>""",
    """<Data Name(\\)?=(\\)?"{1,20}SubjectLogonId(\\)?"{1,20}>({logon_id}[^<]+)<\/Data>""",
    """<Data Name(\\)?=(\\)?"{1,20}ObjectType(\\)?"{1,20}>({file_type}[^<]+)<\/Data>""",
    """<Data Name(\\)?=(\\)?"{1,20}ObjectName(\\)?"{1,20}>({file_path}({file_parent}.+?)[\\\/]+({file_name}(?:[^<\\\/:]+?)(\.({file_ext}\w+))?)|[^\\:<]+)<\/Data>""", 
    """<Data Name(\\)?=(\\)?"{1,20}ProcessName(\\)?"{1,20}>({process}({directory}(?:[^<]+)?[\\\/])?({process_name}[^\\\/"<]+?))<\/Data>""",
    """<Data Name(\\)?=(\\)?"{1,20}AccessList(\\)?"{1,20}>({accesses}.+?)\s(\\t)*""",
    """AccessMask"{1,20}:"{1,20}({access_mask}[^"]+)""", 
  ]
  DupFields = [ "host->dest_host","directory->process_directory" ]
}
```