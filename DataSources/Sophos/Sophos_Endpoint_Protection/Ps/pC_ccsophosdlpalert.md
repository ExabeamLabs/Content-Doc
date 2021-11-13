#### Parser Content
```Java
{
Name = cc-sophos-dlp-alert
  Lms = Splunk
  DataType = "dlp-alert"
  Conditions = [ """CEF:""", """|SkyFormation Cloud Apps Security|""", """"type":"Event::Endpoint::Device::Blocked"""", """Peripheral blocked: """ ]
  Fields = ${SophosParserTemplates.cef-sophos-dlp-alert-1.Fields} [
    """"name":"({alert_name}Peripheral blocked):\s{1,100}({target}[^",]{1,2000})"""",
    """"source":"(n\/a|({user_firstname}[^",\s\\]{1,2000}),?\s{0,100}({user_lastname}[^,"\s\\]{1,2000}))"""",
    """requestClientApplication=({app}[^=]{1,2000})\s{1,100}\w+="""
  ]

cef-sophos-dlp-alert-1 = {
  Vendor = Sophos
  Product = Sophos Endpoint Protection
  Lms = ArcSight
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """"location":"({host}[\w\-.]{1,2000})"""",
    """"when":"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"type":"({alert_type}Event[^"]{1,2000})""",
    """"description":"({alert_name}[^"]{1,2000}?)\.?"""",
    """"name":"({alert_name}[^"]{1,2000})""",
    """"group":"({additional_info}[^"]{1,2000})""",
    """"name":\s{0,100}"(n\/a|({alert_name}[^\:\"\']{1,2000}(\:\s{0,100}\'({target}[^\"\']{1,2000}))?\'))""",
    """"name":\s{0,100}"(n\/a|[^"]{0,2000}? at \'({additional_info}({malware_url}[^"\']{1,2000})))""",
    """"severity":"({alert_severity}[^"]{1,2000})""",
    """"id":"({alert_id}[^"]{1,2000})""",
    """"location":"({src_host}[^"]{1,2000})""",
    """"source":"(n\/a|({user_fullname}[^"\\\(\),]{1,2000}))"""",
    """"source":"(n\/a|({user_lastname}[^",\s]{1,2000}),\s{0,100}({user_firstname}[^,"\s]{1,2000}))""",
    """"source":"(n\/a|(([^\\\s"]{0,2000}\s{1,100}[^\\"]{0,2000}|({domain}[^\\"]{1,2000}))\\+)?(?:Administrator|({user}[^\\\s"]{1,2000})))"""",
    """"source":"(n\/a|({src_host}[\w\-.]{1,2000})\s{0,100}(\(({src_ip}[A-Fa-f:\d.]{1,2000})\))?)"""",
    """"ip":"({src_ip}[A-Fa-f:\d.]{1,2000})""""
  
}
```