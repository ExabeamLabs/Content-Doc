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
    """"Computer"{1,20}:"{1,20}({host}[^"]{1,2000})""",
    """"EventID"{1,20}:({event_code}\d{1,100})""",
    """<Data Name(\\)?=(\\)?"{1,20}SubjectUserSid(\\)?"{1,20}>(?:NONE_MAPPED|({user_sid}[^<]{1,2000}))<\/Data>""",
    """<Data Name(\\)?=(\\)?"{1,20}SubjectUserName(\\)?"{1,20}>(LOCAL SERVICE|({user}[^<]{1,2000}))<\/Data>""",
    """<Data Name(\\)?=(\\)?"{1,20}SubjectDomainName(\\)?"{1,20}>(NT AUTHORITY|({domain}[^<]{1,2000}))<\/Data>""",
    """<Data Name(\\)?=(\\)?"{1,20}SubjectLogonId(\\)?"{1,20}>({logon_id}[^<]{1,2000})<\/Data>""",
    """<Data Name(\\)?=(\\)?"{1,20}ObjectType(\\)?"{1,20}>({file_type}[^<]{1,2000})<\/Data>""",
    """<Data Name(\\)?=(\\)?"{1,20}ObjectName(\\)?"{1,20}>({file_path}({file_parent}.+?)[\\\/]{1,2000}({file_name}(?:[^<\\\/:]{1,2000}?)(\.({file_ext}\w+))?)|[^\\:<]{1,2000})<\/Data>""", 
    """<Data Name(\\)?=(\\)?"{1,20}ProcessName(\\)?"{1,20}>({process}({directory}(?:[^<]{1,2000})?[\\\/])?({process_name}[^\\\/"<]{1,2000}?))<\/Data>""",
    """<Data Name(\\)?=(\\)?"{1,20}AccessList(\\)?"{1,20}>({accesses}.+?)\s(\\t)*""",
    """AccessMask"{1,20}:"{1,20}({access_mask}[^"]{1,2000})""", 
  ]
  DupFields = [ "host->dest_host","directory->process_directory" ]
}
```