#### Parser Content
```Java
{
Name = json-s-proofpoint-email-alert-2
  Conditions = [ """"threatStatus":"""", """"classification":"""", """"threat":""" ]
  Fields = ${PPParserTemplates.s-proofpoint-email-in-1.Fields}[
    """"threat":\s*"({malware_url}[^"]+)""",
    """threatStatus":"({status}[^"]+)"""",
    """\Woutcome=({outcome}.+?)(\s+\w+=|\s*$)""",
  ]
  DupFields = [ "attachment->file_name", "sender->external_address", "recipient->user_email" ]

}
```