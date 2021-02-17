#### Parser Content
```Java
{
Name = abnormal-security-alert
  DataType = "security-alert"
  Conditions = [ """"abx_message_id":""", """"abx_portal_url":""", """"attack_type":""", """"attacked_party":""" ]
  Fields = ${Abnormal-securityParserTemplates.abnormal-security-alert.Fields}[
    """"attack_strategy": "({alert_type}[^"]+)"""",
    """"attack_type": "({alert_name}[^"]+)"""",	
    """"from_address":\s*"({user_email}[^@]+@[^"]+)""""
   ]
}
```