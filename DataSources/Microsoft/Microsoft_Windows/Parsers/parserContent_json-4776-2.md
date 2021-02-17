#### Parser Content
```Java
{
Name = json-4776-2
  DataType = "windows-4776"
  Conditions = ["""attempted to validate the credentials for an account""", """Authentication Package""", """computer_name""", """event_id\":4776"""]
  Fields = ${WinParserTemplates.json-windows-events-2.Fields}[
    """({event_name}The (computer|domain controller) attempted to validate the credentials for an account)""",
    """The ({login_type}computer|domain)(\s\w+)? attempted to validate the credentials""",
    """Workstation\\?"+:\\?"+({dest_host}[^\\]+)\\?"""",
    """TargetUserName\\?"+:\\?"+((({user}[^@\s\\]+?)(?:@({domain}[^\\]+))?)|({user_email}[^@\s]+?@[^\s\.]+?\.[^\s\\]+?))\\?""""
  ]
}
```