#### Parser Content
```Java
{
Name = json-4729
  DataType = "windows-member-removed"
  Conditions = [ """Security ID:""", """Logon ID:""", """A member was removed from a security-enabled""", """raw""", """event_id\":4729""", """computer_name""" ]
  Fields = ${WinParserTemplates.json-windows-events-2.Fields}[
    """({event_name}A member was removed from a security-enabled [\w\s]+ group)""",
    """A member was removed from a security-enabled\s*({group_type}[^\s]+)\s+group""",
    """MemberSid\\?"+:\\?"+({account_id}[^\\]+)\\?"""",
    """MemberName\\?"+:\\?"+({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-\\]+?))\\?"""",
    """TargetSid\\?"+:\\?"+({group_id}[^\\]+)\\?"""",
    """TargetUserName\\?"+:\\?"+({group_name}[^\\]+)\\?"""",
    """TargetDomainName\\?"+:\\?"+({group_domain}[^\\]+)\\?""""
  ]
  DupFields = [ "host->dest_host" ]
}
```