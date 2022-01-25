#### Parser Content
```Java
{
Name = json-4771
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "windows-4771"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [  "4771", """"Kerberos pre-authentication failed.""", """"TicketOptions""" ]
  Fields = [
    """({event_name}Kerberos pre-authentication failed)""",
    """"EventTime":\s{0,100}({time}\d{1,100})""",
    """"EventTime":\s{0,100}"({time}\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"""",
    """"TimeGenerated":"({time}[^"]{0,2000})""",
    """"TimeCreated"{1,20}:"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"Computer":"({host}[^"]{1,2000})"""",
    """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)\s[^\s]{1,2000}\sSkyformation""",
    """@timestamp\\?"{1,20}:\\?"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """"(Hostname|MachineName|(?:winlog\.)?computer_name)\\?":\\?"({host}[^."\\]{0,2000})""",
    """({event_code}4771)""",
    """"(TargetSid|TargetDomainName)\\?":\\?"({user_sid}[^"\\]{0,2000})""",
    """"TargetUserName\\?":\\?"({user}[^"\\]{0,2000})""",
    """"ServiceName\\?":\\?"[^/]{0,2000}\/({domain}[^."\\]{0,2000})""",
    """"(Status|TicketOptions)\\?":\\?"({result_code}[^"\\]{0,2000})""",
    """"((IpAddress)|(ip))\\?":\\?"(?:::[\w]{1,2000}:)?({dest_ip}[a-fA-F:\d.]{1,2000})\\?""""
  ]
  DupFields = ["host->dest_host"]


}
```