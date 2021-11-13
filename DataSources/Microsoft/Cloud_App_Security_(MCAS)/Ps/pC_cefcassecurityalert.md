#### Parser Content
```Java
{
Name = cef-cas-security-alert
  Vendor = Microsoft
  Product = Cloud App Security (MCAS)
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """dproc=mcas-alerts""", """"description":"""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """type":"discovery_ip","label":"({src_ip}[a-fA-F\d.:]{1,2000})"""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """type":"discovery_user","label":"(|({user_email}[^@",]{1,2000}?@[^@",]{1,2000}?)|(({domain}[^"\/]{1,2000})\/)?({user}[^",]{1,2000}?))"""",
    """\Wsuser=(|({user_email}[^@=]{1,2000}?@[^@=]{1,2000})|({uid}(\w+\-){4}\w+)|({user}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """"timestamp":({time}\d{1,100})""",
    """"description":"(|\s{0,100}({additional_info}[^\}]{1,2000}?))\s{0,100}",""",
    """"title":"({alert_name}[^"]{1,2000})""",
    """"URL":"({malware_url}[^"]{1,2000})""",
    """"severityValue":({alert_severity}\d{1,100})""",
    """"_id":"({alert_id}[^"]{1,2000})""",
    """"policyType":"({alert_type}[^"]{1,2000})""",
    """"threatScore"{1,20}:({threat_score}\d{1,100})""",
    """shost=({country_code}[^=]{1,2000}?)\s\w+=""",
    """\srequestClientApplication=({app}[^=]{1,2000}?)\s{0,100}\w+="""
  ]


}
```