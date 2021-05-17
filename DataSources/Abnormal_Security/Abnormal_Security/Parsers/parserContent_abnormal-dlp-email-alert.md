#### Parser Content
```Java
{
Name = abnormal-dlp-email-alert
  DataType = "dlp-email-alert"
  Conditions = [ """"abx_message_id":""", """"abx_portal_url":""", """"attack_type":""", """"Spam"""", """"attacked_party":"""]
  Fields = ${Abnormal-securityParserTemplates.abnormal-security-alert.Fields}[
    """"recipient_address":\s{0,100}"({user_email}[^@]{1,2000}@[^.]{1,2000}\.[^"]{1,2000})"""",
    """"attack_type": "({event_name}[^"]{1,2000})"""",	
  ]
}
abnormal-security-alert = {
    Vendor = Abnormal Security
    Product = Abnormal Security
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Fields = [
      """"received_time":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)"""",
      """exabeam_host=({host}[^\s]{1,2000})""",
      """"threat_id":\s{0,100}"({alert_id}[^"]{1,2000})"""",
      """"subject":\s{0,100}"(|({subject}.+?))\s{0,100}",""",
      """"from_address":\s{0,100}"(|({sender}[^,]{1,2000}?))",""",
      """"to_addresses":\s{0,100}"(|({recipients}({recipient}[^@]{1,2000}@[^,"]{1,2000})[^"]{0,2000}))"""",
      """"internet_message_id":\s{0,100}"<*({message_id}[^>"]{1,2000})>*"""",
      """"auto_remediated":\s{0,100}({outcome}true)""",
      """"abx_portal_url":\s{0,100}"({additional_info}[^"]{1,2000})"""",
	  
    ]

```