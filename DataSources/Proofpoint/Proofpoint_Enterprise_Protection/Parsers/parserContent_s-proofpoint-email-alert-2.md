#### Parser Content
```Java
{
Name = s-proofpoint-email-alert-2
  Conditions = [ """CEF:""", """destinationServiceName=Proofpoint""", """cat=security-alert""", """"threat""" ]
  Fields = ${PPParserTemplates.s-proofpoint-email-in-1.Fields}[
    """"sha256"+:"+({sha256}[^"]+)"+,"md5"+:"+({md5}[^"]+)"+,\s*"filename":\s*"(?!text(\.txt|\.html|-calendar))""",
    """ Category \[({category}[^\]]+?)\]""",
    """"url":"\s*"({malware_url}[^"]+)""",
    """"threat":\s*"({malware_url}[^"]+)""",
    """"threatUrl":\s*"({threat_url}[^"]+?)"""",
    """fromAddress":\s*\[?"({sender}[^"\s,@]+@({external_domain}[^"\s,@]+))"\]?""",
    """toAddresses":\s*\[({recipients}"({recipient}[^"\s@,;]+@({external_domain_recipient}[^"\s,;]+))[^\]]*?)\]""",
    """proto=({alert_name}[^"]+?)\s\w+=""",
    """\Woutcome=({outcome}[^"]+?)(\s+\w+=|\s*$)""",
    """"fromArray":"({outcome}clicksBlocked|clicksPermitted|messagesBlocked|messagesDelivered)""""
  ]
  DupFields = [ "attachment->file_name", "sender->external_address", "recipient->user_email" ]

}
```