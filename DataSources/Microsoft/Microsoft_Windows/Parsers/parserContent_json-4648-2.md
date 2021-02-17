#### Parser Content
```Java
{
Name = json-4648-2
  DataType = "windows-account-switch"
  Conditions = ["""A logon was attempted using explicit credentials""", """Target Server Name""", """computer_name""", """event_id\":4648"""]
  Fields = ${WinParserTemplates.json-windows-events-2.Fields}[
    """({event_name}A logon was attempted using explicit credentials)""",
    """"LogonGuid\\?"+:\\?"\{({user_logon_guid}[^}]+)\}\\?"""",
    """TargetUserName\\?"+:\\?"(LOCAL SYSTEM|({account}[^\\]+))\\?"""",
    """TargetDomainName\\?"+:\\?"(\.|({account_domain}[^\\]+))\\?"""",
    """TargetLogonGuid\\?"+:\\?"\{({account_logon_guid}[^\\}]+)\}\\?"""",
    """TargetServerName\\?"+:\\?"({dest_host}[^\\]+)\\?"""",
    """TargetInfo\\?"+:\\?"({dest_service}[^\s:;\\]+)\\?"""",
    """IpAddress\\?"+:\\?"(?:-|(::[\w]+:)?({src_ip}[a-fA-F:\d.]+))\\?""""
  ]
  DupFields=[ "host->dest_host","src_host_windows->src_host" ]
}
```