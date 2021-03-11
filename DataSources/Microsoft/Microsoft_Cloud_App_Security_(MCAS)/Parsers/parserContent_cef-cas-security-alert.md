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
    """\Wsuser=(|({user_email}[^@=]+?@[^@=]+)|({uid}(\w+\-){4}\w+)|({user}[^=]+?))(\s+\w+=|\s*$)""",
    """"timestamp":({time}\d+)""",
    """"description":"(|\s*({additional_info}[^\}]+?))\s*",""",
    """"title":"({alert_name}[^"]+)""",
    """"URL":"({malware_url}[^"]+)""",
    """"severityValue":({alert_severity}\d+)""",
    """"_id":"({alert_id}[^"]+)""",
    """"policyType":"({alert_type}[^"]+)""",
    """"threatScore"+:({threat_score}\d+)""",
    """shost=({country_code}[^=]+?)\s\w+=""",
    """\srequestClientApplication=({app}[^=]+?)\s*\w+="""
  ]
}
```