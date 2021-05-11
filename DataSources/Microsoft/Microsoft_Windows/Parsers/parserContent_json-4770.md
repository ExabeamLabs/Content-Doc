#### Parser Content
```Java
{
Name = json-4770
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4770"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ "4770", """"A Kerberos service ticket was renewed.""", """"TicketEncryptionType""" ]
  Fields = [
    """({event_name}A Kerberos service ticket was renewed)""",
    """"EventTime":\s{0,100}({time}\d{1,100})""",
    """"TimeGenerated":"({time}[^"]*)""",
    """"{1,20}created"{1,20}:"{1,20}({time}[^"]+)""",
    """"EventTime":\s{0,100}"({time}\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"""",
    """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)\s[^\s]+\sSkyformation""",
    """@timestamp\\?"{1,20}:\\?"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """"(MachineName|Hostname|(?:winlog\.)?computer_name)\\?":\\?"({host}[^."\\]+)""",
    """({event_code}4770)""",
    """"TargetDomainName\\?":\\?"({domain}[^."\\]*)""",
    """"TargetUserName\\?":\\?"({user}[^@"]*)""",
    """"ServiceName\\?":\\?"({service_name}[^"\\]*)""",
    """"ServiceName\\?":\\?"({dest_host}[^"\\]*\$)""",
    """"TicketOptions\\?":\\?"({ticket_options}[^"\\]*)""",
    """"TicketEncryptionType\\?":\\?"({ticket_encryption_type}[^"\\]*)""",
    """"IpAddress\\?":\\?"(?:::[\w]+:)?({src_ip}[a-fA-F:\d.]+)\\?""""
  ]
}
```