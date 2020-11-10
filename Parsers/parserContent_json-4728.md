#### Parser Content
```Java
{
Name = json-4728
  DataType = "windows-member-added"
  Conditions = [ """A member was added to a security-enabled""", """event_id\":4728""", """computer_name""" ]
  Fields = ${WinParserTemplates.json-windows-events-2.Fields}[
    """A member was added to a security-enabled ({group_type}\w+) group""",
    """MemberName\\?"+:\\?"+(-|({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-\\]+?)))\\?"""",
    """MemberSid\\?"+:\\?"+({account_id}[^\\]+)\\?"""",
    """TargetSid\\?"+:\\?"+({group_id}[^\\]+)\\?"""",
    """TargetUserName\\?"+:\\?"+({group_name}[^\\]+)\\?"""",
    """TargetDomainName\\?"+:\\?"+({group_domain}[^\\]+)\\?""""
  ]
  DupFields = [ "host->dest_host" ]
}
```