#### Parser Content
```Java
{
Name = cef-fidelis-alert
  Vendor = Fidelis
  Product = Fidelis Network
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """CEF:""", """|skyformation|""", """cat=security-alert""", """destinationServiceName=Fidelis""", """|security-threat-detected|""" ]
  Fields = [
    """"ALERT_TIME":"({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)"""",
    """"ALERT_ID":"({alert_id}\d+)"""",
    """"RULE_NAME":"({rule}[^"]+)"""",
    """"PROTOCOL":"({protocol}[^"]+)"""",
    """"FILE_NAME":"({file_name}[^"]+a)"""",
    """"SRC_IP":"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"DEST_IP":"({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"HOST_IP":"({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"DEST_PORT":"({dest_port}\d+)"""",
    """"SRC_PORT":"({src_port}\d+)"""",
    """"SHA256":"({sha256_sum}[^"]+)"""",
    """"SUMMARY":"({additional_info}[^"]+)"""",
    """"SRC_COUNTRY_NAME":"(?:unknown|({src_country}[^"]+))"""",
    """"DEST_COUNTRY_NAME":"(?:unknown|({dest_country}[^"]+))"""",
    """"TARGET":"({target}[^"]+)"""",
    """"FIDELIS_SCORE":"({score}\d+)"""",
    """"ACTION":"({alert}[^"]+)"""",
    """"FILE_TYPE":"({file_type}[^"]+)"""",
    """"SEVERITY":"({alert_severity}[^"]+)"""",
    """"SESSION_ID":"({session_id}[^"]+)"""",
    """\smsg=({additional_info}.+)\soldFilePath=""",
    """"APPLICATION_USER":"(({user_email}[^@]+?@[^"]+)|({user}[^"]+?))"""",
    """"MD5":"({md5_sum}[^"]+)""""
  ]
}
```