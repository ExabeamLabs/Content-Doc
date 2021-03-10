#### Parser Content
```Java
{
Name = json-4770
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4770"
  TimeFormat = "MM/dd/yyyy H:mm:ss a"
  Conditions = [ "4770", """"A Kerberos service ticket was renewed.""", """"TicketEncryptionType""" ]
  Fields = [
    """({event_name}A Kerberos service ticket was renewed)""",
    """"TimeGenerated":"({time}[^"]*)""",
    """"EventTime":\s*"({time}\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"""",
    """"(MachineName|Hostname|computer_name)":"({host}[^."]+)""",
    """({event_code}4770)""",
    """"TargetDomainName":"({domain}[^."]*)""",
    """"TargetUserName":"({user}[^@"]*)""",
    """"ServiceName":"({service_name}[^"]*)""",
    """"ServiceName":"({dest_host}[^"]*\$)""",
    """"TicketOptions":"({ticket_options}[^"]*)""",
    """"TicketEncryptionType":"({ticket_encryption_type}[^"]*)""",
    """"IpAddress":"(?:::[\w]+:)?({src_ip}[a-fA-F:\d.]+)""""
  ]
}
```