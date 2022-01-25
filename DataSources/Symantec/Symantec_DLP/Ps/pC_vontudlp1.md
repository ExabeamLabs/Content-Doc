#### Parser Content
```Java
{
Name = vontu-dlp-1
    Vendor = Symantec
    Product = Symantec DLP
    Lms = Splunk
    DataType = "dlp-alert"
    TimeFormat = "dd MMM yyyy HH:mm:ss.a"
    Conditions = [ """Policy Violated: """, """Endpoint Machine: """, """DLP ALERT""", """Application Name: """, """Incident ID: """ ]
    Fields = [
      """\d\d:\d\d:\d\d\s{1,20}({host}[^\s]{1,2000})"""
      """Reported On:\s{1,20}({time}\d{0,2} \w+ \d{1,4} \d{0,2}:\d{0,2}:\d{0,2} (am|pm|PM|AM))"""
      """\sPolicy Violated:\s{1,20}({alert_name}[^:]{1,2000}?)\s{0,20}Reported On:""",
      """({additional_info}DLP ALERT|DLP ALERT[^:]{1,2000}?)\s{1,20}Application Name:""",
      """\sApplication Name:\s{1,100}({app}[^:]{1,2000}?)\s{0,20}Endpoint Machine:"""
      """\WEndpoint Machine:\s{1,100}(?:N\/A|({src_host}[^\s]{1,2000}))""",
      """\sMachine IP:\s{1,100}(?:N\/A|({src_ip}[a-fA-F:\.\d]{1,2000}))""",
      """\sFile Name:\s{1,100}(?:N\/A|({file_name}[^:]{1,2000}?))\s{0,20}Machine IP:""",
      """\WSeverity:\s{1,100}({alert_severity}[^\s]{1,2000})""",
      """\sIncident ID:\s{1,20}({alert_id}\d{1,200})""",
      """\sEndpoint Username:\s{1,20}(({domain}[^\\]{1,2000})\\)?({user}[^\s]{1,2000})""",
      """({alert_type}DLP ALERT)""",
    ]
  

}
```