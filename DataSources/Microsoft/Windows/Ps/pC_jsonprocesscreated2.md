#### Parser Content
```Java
{
Name = json-process-created-2
    Vendor = Microsoft
    Product = Windows
    Lms = Direct
    DataType = "windows-process-created"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = [ """"event_id""", """4688""", """A new process has been created""" ]
    Fields = [
      """"EventTime"{0,20}:"{0,20}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)\s[^\s]{1,2000}\sSkyformation""",
      """"@timestamp"{0,20}:"{0,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d{1,100}Z)""",
      """"Account"{0,20}:"{0,20}(({domain}[^"]{1,2000}?)[\\\/]{1,2000})?({user}[^"\\\/]{1,2000})"""",
      """({event_code}4688)""",
      """"Activity"{0,20}:"{0,20}({event_name}[^"]{1,2000})""",
      """"hostname"{0,20}:"{0,20}({host}[^"]{1,2000})""",
      """"CommandLine"{0,20}:"{0,20}({command_line}[^"]{1,2000})""",
      """"NewProcessId"{0,20}:"{0,20}({process_guid}[^"]{1,2000})""",
      """"NewProcessName"{0,20}:"{0,20}({process}({directory}[^"]{0,2000}?[\\\/]{1,2000})?({process_name}[^"\\\/]{1,2000}))"""",
      """"SubjectLogonId"{0,20}:"{0,20}({login_id}[^"]{1,2000})""",
      """"SubjectUserName"{0,20}:"{0,20}(-|SYSTEM|({user}[^"]{1,2000}?))""""
      """"SubjectDomainName"{0,20}:"{0,20}(-|({domain}[^"]{1,2000}?))""""
    ]
    DupFields = [ "host->dest_host", "directory->process_directory" ]
  

}
```