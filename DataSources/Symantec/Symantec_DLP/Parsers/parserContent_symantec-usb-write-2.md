#### Parser Content
```Java
{
Name = symantec-usb-write-2
  Conditions = [ """type":"""", ""","device":"""", """"action":"File Write"""" ]
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
    """\d+-\d+-\d+T\d+:\d+:\d+\.\d+[\+\-]\d+:\d+\s+({host}[\w\-.]+)\s""",
    """"@timestamp":"({time}\d+-\d+-\d+T\d+:\d+:\d+\.\d+Z)""",
    """"hostname":"({dest_host}[\w\-.]+)""",
    """"action":"({activity}[^"]+)""",
    """"user":\{"name":"(system|({user}[^"\s]+))"""",
    """"ip":"(0.0.0.0|({dest_ip}[A-Fa-f:\d.]+))""",
    """"executable":"({process}({directory}(?:[^,"]+)?[\\\/])?({process_name}[^\\\/,"]+?))"""",
    """"path":"(|({file_path}({file_parent}[^"]*?[\\\/]*)(|({file_name}[^\\\/"]*?(\.({file_ext}[^\\\/\.\s"]*))?))))\s*"""",
    """"size":({bytes}\d+)""",
    """({device_type}(CD-DVD|USB))""",
  ]

```