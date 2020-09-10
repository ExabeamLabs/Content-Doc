#### Parser Content
```Java
{
Name = securelink-login-failed
  DataType = "failed-app-login"
  Conditions = [  """Login failed:""", """SecureLink:""", """User:""" ]
  Fields = ${SecureLinkParserTemplates.securelink-events.Fields}[
  """({event_name}Login failed):\s({failure_reason}[^.]+)""" 
  ]
}
${NetWrixParserTemplates.netwrix-app-activity-2}{
  Name = netwrix-ad-account-unlocked
  DataType = "windows-account-enabled"
  Conditions = [ """CEF:0|Netwrix|Active Directory|""", """|Modified user|""", """msg=User Account Unlocked""" ]
  Fields = ${NetWrixParserTemplates.netwrix-app-activity-2.Fields}[
    """CEF:0\|Netwrix\|Active Directory\|[^\|]+\|[^\|]+\|({activity}[^\|]+)\|""",
    """cat=user.+?filePath=\\+?([^\\]+\\+)*?({target_user}[^\\]+) start=""",
  ]
}
```