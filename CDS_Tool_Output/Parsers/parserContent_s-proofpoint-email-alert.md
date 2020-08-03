#### Parser Content
```Java
{
Name = s-proofpoint-email-alert-2
  Conditions = [ """CEF:""", """destinationServiceName=Proofpoint""", """cat=security-alert""", """"threat":""" ]
  Fields = ${PPParserTemplates.s-proofpoint-email-in-1.Fields}[
    """"threat":\s*"({malware_url}[^"]+)""",
    """proto=({alert_name}.+?)\s\w+=""",
    """\Woutcome=({outcome}.+?)(\s+\w+=|\s*$)""",
  ]
  DupFields = [ "attachment->file_name", "sender->external_address", "recipient->user_email" ]

}
```