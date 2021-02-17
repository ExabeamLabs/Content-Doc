#### Parser Content
```Java
{
Name = aruba-local-logon-1
  DataType = "local-logon"
  Conditions = [ """CEF:""", """"ident":""", """"extradata":""", """"ttam_file":""", """"ttam_reporter":""", """Administrative user""", """authenticated successfully """]
  Fields = ${ArubaParserTemplates.cef-aruba-nac-logon-2.Fields}[
    """Administrative user '({user}[^']+)'"""
  ] 
}
```