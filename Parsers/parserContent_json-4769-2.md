#### Parser Content
```Java
{
Name = json-4769-2
  DataType = "windows-4769"
  Conditions = ["""A Kerberos service ticket was requested""", """Account Name""", """computer_name""", """event_id\":4769"""]
  Fields = ${WinParserTemplates.json-windows-events-2.Fields}[
    """({event_name}A Kerberos service ticket was requested)""",
    """TargetUserName\\?"+:\\?"+((({user}[^@\s\\]+?)(?:@({domain}[^\\]+))?)|({user_email}[^@\s]+?@[^\s\.]+?\.[^\s\\]+?))\\?"""",
    """TargetDomainName\\?"+:\\?"+({domain}[^\\]+)""",
    """ServiceName\\?"+:\\?"+({dest_host}[^\s\\]+)""",
    """IpAddress\\?"+:\\?"+(::[\w]+:)?({src_ip}[\da-fA-F.:]+)\\?"""",
    """Status\\?"+:\\?"+({result_code}[^\s\\]+)""",
    """TicketOptions\\?"+:\\?"+({ticket_options}[^\s\\]+)""",
    """TicketEncryptionType\\?"+:\\?"+({ticket_encryption_type}[^\s\\]+)"""
 ]
 DupFields = ["dest_host->service_name"]
}
```