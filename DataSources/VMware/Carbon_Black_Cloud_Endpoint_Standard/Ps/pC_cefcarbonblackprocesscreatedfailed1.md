#### Parser Content
```Java
{
Name = cef-carbonblack-process-created-failed-1
  DataType = "process-created"
  IsHVF = true
  Conditions = [ """threatIndicators""" , """"eventType":"SYSTEM_API_CALL"""", """ unsuccessfully attempted """ ]

cef-carbonblack-events-1 {
  Vendor = VMware
  Product = Carbon Black Cloud Endpoint Standard
  Lms = ArcSight
  TimeFormat = "epoch"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """"eventTime":({time}\d{1,2000}),""",
    """"deviceIpAddress":"({src_ip}[a-fA-F:\d.]{1,2000})"""",
    """"deviceName":"(({domain}[^\\\s"]{1,2000})\\{1,20})?({src_host}[^\\\s"]{1,2000})"""",
    """"email":"(({domain}[^\\"]{1,2000})\\{1,20})?(HiveStreamingService|SYSTEM|({user}[^\s"@]{1,2000}))"""",    
    """"eventType":"({alert_name}[^"]{1,2000})"""",
    """"applicationName":"({process_name}[^"]{1,2000})"""",
    """"targetPriorityType":"({alert_severity}[^"]{1,2000})"""",
    """"eventType":"({alert_type}[^"]{1,2000})"""",
    """"threatIndicators":\[?"({alert_type}[^"]{1,2000})"""",
    """"applicationPath":"({process}(({directory}[^"=,]{1,2000}?)[\\\/]{1,20})?({process_name}[^\/\\"]{1,2000}))"""",
    """"peerFqdn":"(::|({web_domain}[^"]{1,2000}))"""",
    """"peerFqdn":"[^"\s]{0,2000}?({top_domain}[^\/\.\s"]{1,2000}(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)){1,2000})""",
    """"destAddress":"({dest_ip}[a-fA-F\d:.]{1,2000})"""",
    """"name":"({file_path}(\w:|\\\\)[^"]{1,2000})"""",
    """"name":"({file_name}[^\\\/"]{1,2000}?(\.({file_ext}[^"]{1,2000}))?)"""",
    """"name":"({file_parent}(\w:|\\\\)[^"]{1,2000}?)\\{1,20}(?:[^\\"]{1,2000}?)"""",
    """>\s{0,100}({file_name}[^<"']{1,2000}?)<\/link><\/share>"{0,20}\s{0,100}was created by the application""",
    """"name":"({file_path}(({file_parent}\w+:[^"]{1,2000}?)\\{1,20})\s{0,100}({file_name}[^"\\,:]{1,2000}?))"""",
    """"eventId":"({alert_id}[^"]{1,2000})"""",
    """"parentApp":\{[^}]{1,2000}"md5Hash":"({parent_md5hash}[^"]{1,2000})""",
    """"parentApp":\{[^}]{1,2000}"sha256Hash":"({parent_sha256}[^"]{1,2000})"""",
    """"targetApp":\{[^}]{1,2000}"sha256Hash":"({target_sha256}[^"]{1,2000})"""",
    """"targetApp":\{[^}]{1,2000}"md5Hash":"({target_md5hash}[^"]{1,2000})"""",
    """"selectedApp":\{[^}]{1,2000}"md5Hash":"({selected_md5hash}[^"]{1,2000})"""",
    """"selectedApp":\{[^}]{1,2000}"sha256Hash":"({selected_sha256}[^"]{1,2000})"""",
  ]
  DupFields = [ "directory->process_directory" 
}
```