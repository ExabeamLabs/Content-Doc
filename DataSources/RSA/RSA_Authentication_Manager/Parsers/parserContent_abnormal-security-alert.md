#### Parser Content
```Java
{
Name = abnormal-security-alert
  DataType = "security-alert"
  Conditions = [ """"abx_message_id":""", """"abx_portal_url":""", """"attack_type":""", """"attacked_party":""" ]
  Fields = ${Abnormal-securityParserTemplates.abnormal-security-alert.Fields}[
    """"attack_strategy": "({alert_type}[^"]+)"""",
    """"attack_type": "({alert_name}[^"]+)"""",	
    """"from_address":\s{0,100}"({user_email}[^@]+@[^"]+)""""
   ]
}
abnormal-security-alert = {
    Vendor = Abnormal Security
    Product = Abnormal Security
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Fields = [
      """"received_time":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)"""",
      """exabeam_host=({host}[^\s]+)""",
      """"threat_id":\s{0,100}"({alert_id}[^"]+)"""",
      """"subject":\s{0,100}"(|({subject}.+?))\s{0,100}",""",
      """"from_address":\s{0,100}"(|({sender}[^,]+?))",""",
      """"to_addresses":\s{0,100}"(|({recipients}({recipient}[^@]+@[^,"]+)[^"]*))"""",
      """"internet_message_id":\s{0,100}"<*({message_id}[^>"]+)>*"""",
      """"auto_remediated":\s{0,100}({outcome}true)""",
      """"abx_portal_url":\s{0,100}"({additional_info}[^"]+)"""",
	  
    ]

```