#### Parser Content
```Java
{
Name = abnormal-security-alert
  DataType = "security-alert"
  Conditions = [ """"abx_message_id":""", """"abx_portal_url":""", """"attack_type":""", """"attacked_party":""" ]
  Fields = ${Abnormal-securityParserTemplates.abnormal-security-alert.Fields}[
    """"attack_strategy": "({alert_type}[^"]{1,2000})"""",
    """"attack_type": "({alert_name}[^"]{1,2000})"""",	
    """"from_address":\s{0,100}"({user_email}[^@]{1,2000}@[^"]{1,2000})""""
   ]
},	
{
  Name = rsa-authentication-successful
  Vendor = RSA
  Product = RSA Authentication Manager
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd HH:mm:ss:SSS zzz"
  Conditions = [ """,Authentication Success,Valid User,""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """({time}\d\d\d\d-\d\d-\d\d\s{1,100}\d\d:\d\d:\d\d:\d{1,100}\s{1,100}\w+)""",
    """\s\d\d:\d\d:\d\d:\d{1,100}[^,]{1,2000}\,([^,]{0,2000}\,){3}(\s{0,100}|({user}[^,\s]{1,2000}))\,([^,]{0,2000}\,){6}(\s{0,100}|({src_ip}[A-Fa-f:\d.]{1,2000}))\,(\s{0,100}|({src_port}\d{1,100}))\,(\s{0,100}|({dest_ip}[A-Fa-f:\d.]{1,2000}))\,""",
    """({event_name}Authentication Success)""",
    """({outcome}Success)"""
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