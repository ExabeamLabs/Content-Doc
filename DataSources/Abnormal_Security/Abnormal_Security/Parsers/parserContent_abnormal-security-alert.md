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
abnormal-security-alert = {
    Vendor = Abnormal Security
    Product = Abnormal Security
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Fields = [
      """"received_time":\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)"""",
      """exabeam_host=({host}[^\s]+)""",
      """"threat_id":\s*"({alert_id}[^"]+)"""",
      """"subject":\s*"(|({subject}.+?))\s*",""",
      """"from_address":\s*"(|({sender}[^,]+?))",""",
      """"to_addresses":\s*"(|({recipients}({recipient}[^@]+@[^,"]+)[^"]*))"""",
      """"internet_message_id":\s*"<*({message_id}[^>"]+)>*"""",
      """"auto_remediated":\s*({outcome}true)""",
      """"abx_portal_url":\s*"({additional_info}[^"]+)"""",
	  
    ]

```