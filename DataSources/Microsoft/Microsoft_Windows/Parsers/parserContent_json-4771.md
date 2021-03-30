#### Parser Content
```Java
{
Name = json-4771
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4771"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [  "4771", """"Kerberos pre-authentication failed.""", """"TicketOptions""" ]
  Fields = [
    """({event_name}Kerberos pre-authentication failed)""",
    """"EventTime":\s*"({time}\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"""",
    """"TimeGenerated":"({time}[^"]*)""",
    """"(Hostname|MachineName|computer_name)":"({host}[^."]*)""",
    """({event_code}4771)""",
    """"(TargetSid|TargetDomainName)":"({user_sid}[^"]*)""",
    """"TargetUserName":"({user}[^"]*)""",
    """"ServiceName":"[^/]*\/({domain}[^."]*)""",
    """"(Status|TicketOptions)":"({result_code}[^"]*)""",
    """"IpAddress":"(?:::[\w]+:)?({dest_ip}[a-fA-F:\d.]+)""""
  ]
}
```