#### Parser Content
```Java
{
Name = bro-remote-logon-2
  Product = Zeek Network Security Monitor
  DataType = "remote-logon"
  Conditions = [ """protocol""", """"rdp"""", """zeek""", """type""" ]
  Fields = ${BroParserTemplates.bro-activity-1.Fields}[
    """"+rdp"+.+?result"+:"+({outcome}[^"]+)""",
  ]
}
```