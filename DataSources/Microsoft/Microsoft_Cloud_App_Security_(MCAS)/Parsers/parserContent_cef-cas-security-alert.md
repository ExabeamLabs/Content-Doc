#### Parser Content
```Java
{
Name = cef-cas-security-alert
  Vendor = Microsoft
  Product = Microsoft Cloud App Security (MCAS)
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """dproc=mcas-alerts""", """"description":"""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """type":"discovery_ip","label":"({src_ip}[a-fA-F\d.:]+)"""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """type":"discovery_user","label":"(|({user_email}[^@",]+?@[^@",]+?)|(({domain}[^"\/]+)\/)?({user}[^",]+?))"""",
    """\Wsuser=(|({user_email}[^@=]+?@[^@=]+)|({uid}(\w+\-){4}\w+)|({user}[^=]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """"timestamp":({time}\d{1,100})""",
    """"description":"(|\s{0,100}({additional_info}[^\}]+?))\s{0,100}",""",
    """"title":"({alert_name}[^"]+)""",
    """"URL":"({malware_url}[^"]+)""",
    """"severityValue":({alert_severity}\d{1,100})""",
    """"_id":"({alert_id}[^"]+)""",
    """"policyType":"({alert_type}[^"]+)""",
    """"threatScore"{1,20}:({threat_score}\d{1,100})""",
    """shost=({country_code}[^=]+?)\s\w+=""",
    """\srequestClientApplication=({app}[^=]+?)\s{0,100}\w+="""
  ]
}
```