#### Parser Content
```Java
{
Name = aruba-nac-failed-1
  DataType = "nac-failed-logon"
  Conditions = [ """CEF:""", """"ident":""", """"extradata":""", """"ttam_file":""", """"ttam_reporter":""", """User Authentication failed.""", """method"""]
  Fields = ${ArubaParserTemplates.cef-aruba-nac-logon-2.Fields}[
    """authmethod\\*=({auth_type}[^=]+)\s+\w+\\*=""",
  ]
}
```