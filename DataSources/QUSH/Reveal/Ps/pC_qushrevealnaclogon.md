#### Parser Content
```Java
{
Name = qush-reveal-nac-logon
  DataType = "nac-logon"
  Conditions = [ """reveal""", """"wifi"""", """"tags":""", """"riskybehavior"""" ]
  Fields = ${QUSHRevealParserTemplates.qush-reveal-events.Fields} [
    """({activity}wifi)"""
  ]

qush-reveal-events = {
    Vendor = QUSH
    Product = Reveal
    Lms = Direct
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
    Fields = [
      """"agent_hostname"{1,10}:"{1,10}({host}[^"]{1,2000})"""",
      """"timestamp"{1,10}:"{1,10}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d{1,10}Z)"""",
      """"description"{1,10}:"{1,10}({additional_info}[^\n]{1,2000}?)\s{0,100}",""",
      """"username":"(({user_fullname}[^\\\s"]{1,2000}\s[^"\\]{1,2000})|(({domain}[^"\s\\]{1,2000})\\{1,20})?({user}[^"\s]{1,2000}))"""",
      """"destination_ip":\["({dest_ip}[a-fA-F\d:\.]{1,2000})"\]""",
      """"destination_port":\["({dest_port}\d{1,5})"\]""",
      """"source_ip":\["({src_ip}[a-fA-F\d:\.]{1,2000})"\]""",
      """"source_port":\["({src_port}\d{1,5})"\]"""
      """"binary_path"{1,10}:"{1,10}({process}({process_directory}[^"]{1,2000}?)\\{1,20}({process_name}[^"\\]{1,2000}))"""",
      """"binary_name"{1,10}:\["{1,10}({process_name}[^",]{1,2000})"\]""",
      """"anonymised_description"{1,10}:"{1,10}({event_name}[^\n]{1,2000}?)",""",
      """"accountname"{1,10}:\["{1,10}((({domain}[^\\",]{1,1000})\\{1,10})?({user}[^",]{1,2000}))"\]""",
      """"file_name":\["({file_name}[^"]{1,2000}?(\.({file_ext}[^"\.:]{1,2000})(:[^"]{1,2000})?)?)"""",
      """"file_path":\["({file_path}[^"]{1,2000})"""",
      """"tags":\[[^\]]{0,2000}?"({tag}[^"\]]{1,2000})"\]""",
      """"agent_hostname":"({host}[\w\-\.]{1,2000})"""",
      """"created_by":"policy:[^"]{1,2000}?name=({event_name}[^"]{1,2000})""""
    
}
```