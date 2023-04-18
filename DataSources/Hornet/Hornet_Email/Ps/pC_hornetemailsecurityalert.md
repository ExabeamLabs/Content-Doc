#### Parser Content
```Java
{
Name = hornet-email-security-alert
  Vendor = Hornet
  Product = Hornet Email
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """main_domain=""", """owner=""", """smtp_code=""", """crypt_type=""", """from_hdr=""", """update_nr=""", """type=5""" ]
  Fields = [
    """date=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """reason="({alert_name}[^"]{1,2000})""",
    """type=({alert_type}5)""",
    """msgid="({alert_id}[^"]{1,2000})""",
    """dir=({direction}1|2)""",
    """main_domain=({domain}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
    """from=({sender}[^@\s]{1,2000}?@[^\s]{1,2000})""",
    """to=({recipient}[^@\s]{1,2000}?@[^\s]{1,2000})""",
    """src_host=((?i)unknown|({src_host}[^\s]{1,2000}))""",
    """src_ip=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """dst_ip=(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^\s]{1,2000}))""",
    """attachments="[^0"]#({attachments}[^"]{1,2000})""",
    """subject="[ \s]{0,2000}({subject}[^"]{1,2000}?)[ \s]{0,2000}"""",
  ]
  DupFields = [ "alert_type->alert_severity" ]


}
```