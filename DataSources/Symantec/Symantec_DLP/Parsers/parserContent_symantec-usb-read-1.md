#### Parser Content
```Java
{
Name = symantec-usb-read-1
  Conditions = [ """type":"""", ""","device":"""", """"action":"File Read"""" ]
  Fields = ${SymantecParserTemplates.symantec-usb-activity.Fields}[
     """device":"({device_id}[^"]+)""",
  ] 
}
symantec-usb-activity = {
  Vendor = Symantec
  Product = Symantec DLP
  Lms = Direct
  DataType = "usb-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}[\+\-]\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]+)\s""",
    """"@timestamp":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)""",
    """"hostname":"({dest_host}[\w\-.]+)""",
    """"action":"({activity}[^"]+)""",
    """"user":\{"name":"(system|({user}[^"\s]+))"""",
    """"ip":"(0.0.0.0|({dest_ip}[A-Fa-f:\d.]+))""",
    """"executable":"({process}({directory}(?:[^,"]+)?[\\\/])?({process_name}[^\\\/,"]+?))"""",
    """"path":"(|({file_path}({file_parent}[^"]*?[\\\/]*)(|({file_name}[^\\\/"]*?(\.({file_ext}[^\\\/\.\s"]*))?))))\s{0,100}"""",
    """"size":({bytes}\d{1,100})""",
    """({device_type}(CD-DVD|USB))""",
  ]

```