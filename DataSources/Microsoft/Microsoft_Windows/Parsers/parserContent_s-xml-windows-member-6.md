#### Parser Content
```Java
{
Name = s-xml-windows-member-6
  DataType = "windows-member-removed"
  Conditions = [ "4757", "<Data Name='TargetSid'>", """A member was removed from a security-enabled universal group""" ]
  Fields = ${WinParserTemplates.s-xml-windows-member.Fields} [
    """"EventID":"({event_code}\d+)""",
  ]
}
```