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
     """Hostname":\s{0,100}"({host}[^"]+)""",
     """EventTime":\s{0,100}"({time}[^"]+)""",
     """({event_code}5156)""",
     """({event_name}The Windows Filtering Platform has permitted a connection)""",
     """Layer Name:\s{0,100}[\\trn]*({layer_name}[^\s]+)""",
     """Protocol":\s{0,100}"({ms_protocol_num}\d{1,100})""",
     """ProcessID":\s{0,100}"({pid}[^"]+)""",
     """Application":\s{0,100}"({process}({directory}[^"]+)[\\\/]({process_name}[^"]+))"""",
     """Direction":\s{0,100}"({direction}[^"]+)"""",
     """Direction:\s{0,100}[\\rtn]*({direction}(Inbound|Outbound))""",
     """DestAddress":\s{0,100}"({dest_ip}[a-fA-F\d:\.]+)""",
     """DestPort":\s{0,100}"({dest_port}\d{1,100})""",
     """SourceAddress":\s{0,100}"({src_ip}[a-fA-F\d:\.]+)""",
     """SourcePort":\s{0,100}"({src_port}\d{1,100})""",
  ]
}
```