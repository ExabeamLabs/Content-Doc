#### Parser Content
```Java
{
Name = qush-reveal-web-activity-1
  DataType = "web-activity"
  Conditions = [ """reveal""", """"flightrisk"""", """"tags":""", """"jobhunting"""" ]
  Fields = ${QUSHRevealParserTemplates.qush-reveal-events.Fields} [
    """({protocol}http)""",
    """"url"{1,10}:\["{1,10}({full_url}[^"]{1,2000})"""",
    """"host"{1,10}:\["{1,10}({web_domain}[^"]{1,2000})""""
  ]

qush-reveal-events = {
    Vendor = QUSH
    Product = Reveal
    Lms = Direct
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
    Fields = [
      """"agent_hostname"{1,10}:"{1,10}({host}[^"]{1,2000})"""",
      """"timestamp"{1,10}:"{1,10}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d{1,10}Z)"""",
      """"description"{1,10}:"{1,10}({additional_info}[^\n]{1,2000}?)",""",
      """"username"{1,10}:"{1,10}((({domain}[^\\",]{1,1000})\\{1,10})?({user}[^",]{1,2000}))"""",
      """"source_ip"{1,10}:\["{1,10}({src_ip}[A-Fa-f\d:.]{1000})"""",
      """"binary_name"{1,10}:\["{1,10}({file_name}[^",]{1,2000}(\.({file_ext}[\w]{1,2000}))?)"\]""",
      """"binary_path"{1,10}:"{1,10}({file_path}[^"]{1,2000})"""",
      """"anonymised_description"{1,10}:"{1,10}({event_name}[^\n]{1,2000}?)",""",
      """"accountname"{1,10}:\["{1,10}((({domain}[^\\",]{1,1000})\\{1,10})?({user}[^",]{1,2000}))"\]""" 
    
}
```