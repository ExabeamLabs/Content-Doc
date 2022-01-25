#### Parser Content
```Java
{
Name = symantec-usb-read-1
  Conditions = [ """type":"""", ""","device":"""", """"action":"File Read"""" ]
  Fields = ${SymantecParserTemplates.symantec-usb-activity.Fields}[
     """device":"({device_id}[^"]{1,2000})""",
  ] 
}
symantec-usb-activity = {
  Vendor = Symantec
  Product = Symantec DLP
  Lms = Direct
  DataType = "usb-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}[\+\-]\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]{1,2000})\s""",
    """"@timestamp":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)""",
    """"hostname":"({dest_host}[\w\-.]{1,2000})""",
    """"action":"({activity}[^"]{1,2000})""",
    """"user":\{"name":"(system|({user}[^"\s]{1,2000}))"""",
    """"ip":"(0.0.0.0|({dest_ip}[A-Fa-f:\d.]{1,2000}))""",
    """"executable":"({process}({directory}(?:[^,"]{1,2000})?[\\\/])?({process_name}[^\\\/,"]{1,2000}?))"""",
    """"path":"(|({file_path}({file_parent}[^"]{0,2000}?[\\\/]{0,2000})(|({file_name}[^\\\/"]{0,2000}?(\.({file_ext}[^\\\/\.\s"]{0,2000}))?))))\s{0,100}"""",
    """"size":({bytes}\d{1,100})""",
    """({device_type}(CD-DVD|USB))""",
  ]

```