#### Parser Content
```Java
{
Name = json-4770
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "windows-4770"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ "4770", """"A Kerberos service ticket was renewed.""", """"TicketEncryptionType""" ]
  Fields = [
    """({event_name}A Kerberos service ticket was renewed)""",
    """"EventTime":\s{0,100}({time}\d{1,100})""",
    """"TimeGenerated":"({time}[^"]{0,2000})""",
    """"{1,20}created"{1,20}:"{1,20}({time}[^"]{1,2000})""",
    """"EventTime":\s{0,100}"({time}\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"""",
    """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)\s[^\s]{1,2000}\s""",
    """@timestamp\\?"{1,20}:\\?"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """"(MachineName|Hostname|(?:winlog\.)?computer_name)\\?":\\?"({host}[^."\\]{1,2000})""",
    """({event_code}4770)""",
    """"TargetDomainName\\?":\\?"({domain}[^."\\]{0,2000})""",
    """"TargetUserName\\?":\\?"({user}[^@"]{0,2000})""",
    """"ServiceName\\?":\\?"({service_name}[^"\\]{0,2000})""",
    """"ServiceName\\?":\\?"({dest_host}[^"\\]{0,2000}\$)""",
    """"TicketOptions\\?":\\?"({ticket_options}[^"\\]{0,2000})""",
    """"TicketEncryptionType\\?":\\?"({ticket_encryption_type}[^"\\]{0,2000})""",
    """"IpAddress\\?":\\?"(?:::[\w]{1,2000}:)?({src_ip}[a-fA-F:\d.]{1,2000})\\?""""
  ]


}
```