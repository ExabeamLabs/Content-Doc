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
    """"ALERT_ID":"({alert_id}\d{1,100})"""",
    """"RULE_NAME":"({rule}[^"]{1,2000})"""",
    """"PROTOCOL":"({protocol}[^"]{1,2000})"""",
    """"FILE_NAME":"({file_name}[^"]{1,2000}a)"""",
    """"SRC_IP":"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"DEST_IP":"({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"HOST_IP":"({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"DEST_PORT":"({dest_port}\d{1,100})"""",
    """"SRC_PORT":"({src_port}\d{1,100})"""",
    """"SHA256":"({sha256_sum}[^"]{1,2000})"""",
    """"SUMMARY":"({additional_info}[^"]{1,2000})"""",
    """"SRC_COUNTRY_NAME":"(?:unknown|({src_country}[^"]{1,2000}))"""",
    """"DEST_COUNTRY_NAME":"(?:unknown|({dest_country}[^"]{1,2000}))"""",
    """"TARGET":"({target}[^"]{1,2000})"""",
    """"FIDELIS_SCORE":"({score}\d{1,100})"""",
    """"ACTION":"({alert}[^"]{1,2000})"""",
    """"FILE_TYPE":"({file_type}[^"]{1,2000})"""",
    """"SEVERITY":"({alert_severity}[^"]{1,2000})"""",
    """"SESSION_ID":"({session_id}[^"]{1,2000})"""",
    """\smsg=({additional_info}.+)\soldFilePath=""",
    """"APPLICATION_USER":"(({user_email}[^@]{1,2000}?@[^"]{1,2000})|({user}[^"]{1,2000}?))"""",
    """"MD5":"({md5_sum}[^"]{1,2000})""""
  ]
}
```