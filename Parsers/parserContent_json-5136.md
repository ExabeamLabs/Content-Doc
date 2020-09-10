#### Parser Content
```Java
{
Name = json-5136-1
  DataType = "windows-password-change"
  Conditions = [ """"event_id":5136""", """A directory service object was modified""" ]
  Fields = ${WinParserTemplates.json-windows-events-1.Fields}[
    """({event_name}A directory service object was modified)""",
    """"ObjectDN"+:"+({object_dn}[^"]+)""",
    """"ObjectClass"+:"+({object_class}[^"]+)""",
  ]
}
```