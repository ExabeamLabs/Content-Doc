#### Parser Content
```Java
{
Name = json-microsoft-scep-epp-alert
  Vendor = Microsoft
  Product = Windows Defender
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"threatname":"""", """"scepmaldetecttime":"""" ]
  Fields = [
    """"username":"({user_id}[^"]+)""",
    """"threatname":"({alert_name}[^"]+)""",
    """"threatid":({threat_id}\d{1,100})""",
    """"targethost":"({src_host}[^"]+)""",
    """"severityid":({alert_severity}\d{1,100})""",
    """"scepmaldetecttime":"({time}[^"]+)""",
    """"process":"({process}({directory}[^"]*?)({process_name}[^"\\\/]+))"""",
    """"path":"({malware_url}[^"]+)""",
    """"ntdomain":"({domain}[^"]+)""",
    """"name":"({alert_type}[^"]+)""",
    """"maliciousfilect":({malicious_file_count}\d{1,100})""",
    """"mal_id":({malware_id}\d{1,100})""",
    """"executionstatus":({execution_status}\d{1,100})""",
    """"errorcode":\-?({error_code}\d{1,100})""",
    """"cleanaction":"({outcome}[^"]+)""",
    """"category":"({threat_category}[^"]+)""",
    """"actionsuccess":({action_success}[^,]+)""",
    """"@version":"({version}[^"]+)""",
  ]
}
```