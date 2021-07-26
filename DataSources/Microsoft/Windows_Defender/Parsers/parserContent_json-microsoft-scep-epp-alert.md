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
    """"username":"({user_id}[^"]{1,2000})""",
    """"threatname":"({alert_name}[^"]{1,2000})""",
    """"threatid":({threat_id}\d{1,100})""",
    """"targethost":"({src_host}[^"]{1,2000})""",
    """"severityid":({alert_severity}\d{1,100})""",
    """"scepmaldetecttime":"({time}[^"]{1,2000})""",
    """"process":"({process}({directory}[^"]{0,2000}?)({process_name}[^"\\\/]{1,2000}))"""",
    """"path":"({malware_url}[^"]{1,2000})""",
    """"ntdomain":"({domain}[^"]{1,2000})""",
    """"name":"({alert_type}[^"]{1,2000})""",
    """"maliciousfilect":({malicious_file_count}\d{1,100})""",
    """"mal_id":({malware_id}\d{1,100})""",
    """"executionstatus":({execution_status}\d{1,100})""",
    """"errorcode":\-?({error_code}\d{1,100})""",
    """"cleanaction":"({outcome}[^"]{1,2000})""",
    """"category":"({threat_category}[^"]{1,2000})""",
    """"actionsuccess":({action_success}[^,]{1,2000})""",
    """"@version":"({version}[^"]{1,2000})""",
  ]
}
```