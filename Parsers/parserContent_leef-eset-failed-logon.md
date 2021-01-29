#### Parser Content
```Java
{
Name = leef-eset-failed-logon
  DataType = "failed-logon"
  Conditions = [ """LEEF:""", """|ESET|RemoteAdministrator|""", """cat=ESET RA Audit Event""", """Failed native user""" ]
  Fields = ${ESETParserTemplates.eset-activity.Fields}[
    """\Wtarget=({object}[^\s]+)\s*"""
  ]
}
```