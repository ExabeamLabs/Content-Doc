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
     """Hostname":\s*"({host}[^"]+)""",
     """EventTime":\s*"({time}[^"]+)""",
     """({event_code}5156)""",
     """({event_name}The Windows Filtering Platform has permitted a connection)""",
     """Layer Name:\s*[\\trn]*({layer_name}[^\s]+)""",
     """Protocol":\s*"({ms_protocol_num}\d+)""",
     """ProcessID":\s*"({pid}[^"]+)""",
     """Application":\s*"({process}({directory}[^"]+)[\\\/]({process_name}[^"]+))"""",
     """Direction":\s*"({direction}[^"]+)"""",
     """Direction:\s*[\\rtn]*({direction}(Inbound|Outbound))""",
     """DestAddress":\s*"({dest_ip}[a-fA-F\d:\.]+)""",
     """DestPort":\s*"({dest_port}\d+)""",
     """SourceAddress":\s*"({src_ip}[a-fA-F\d:\.]+)""",
     """SourcePort":\s*"({src_port}\d+)""",
  ]
}
```