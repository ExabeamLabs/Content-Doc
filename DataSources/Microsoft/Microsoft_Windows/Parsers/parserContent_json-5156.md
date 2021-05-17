#### Parser Content
```Java
{
Name = json-5156
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "process-network"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """"EventID":5156""", """The Windows Filtering Platform has permitted a connection""" ]
  Fields = [
     """Hostname":\s{0,100}"({host}[^"]{1,2000})""",
     """EventTime":\s{0,100}"({time}[^"]{1,2000})""",
     """({event_code}5156)""",
     """({event_name}The Windows Filtering Platform has permitted a connection)""",
     """Layer Name:\s{0,100}[\\trn]{0,2000}({layer_name}[^\s]{1,2000})""",
     """Protocol":\s{0,100}"({ms_protocol_num}\d{1,100})""",
     """ProcessID":\s{0,100}"({pid}[^"]{1,2000})""",
     """Application":\s{0,100}"({process}({directory}[^"]{1,2000})[\\\/]({process_name}[^"]{1,2000}))"""",
     """Direction":\s{0,100}"({direction}[^"]{1,2000})"""",
     """Direction:\s{0,100}[\\rtn]{0,2000}({direction}(Inbound|Outbound))""",
     """DestAddress":\s{0,100}"({dest_ip}[a-fA-F\d:\.]{1,2000})""",
     """DestPort":\s{0,100}"({dest_port}\d{1,100})""",
     """SourceAddress":\s{0,100}"({src_ip}[a-fA-F\d:\.]{1,2000})""",
     """SourcePort":\s{0,100}"({src_port}\d{1,100})""",
  ]
}
```