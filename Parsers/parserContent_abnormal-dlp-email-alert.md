#### Parser Content
```Java
{
Name = abnormal-dlp-email-alert
  DataType = "dlp-email-alert"
  Conditions = [ """"abx_message_id":""", """"abx_portal_url":""", """"attack_type":""", """"Spam"""", """"attacked_party":"""]
  Fields = ${Abnormal-securityParserTemplates.abnormal-security-alert.Fields}[
    """"recipient_address":\s*"({user_email}[^@]+@[^.]+\.[^"]+)"""",
    """"attack_type": "({event_name}[^"]+)"""",	
  ]
}
```