#### Parser Content
```Java
{
Name = windows-kinesis-firehose-5156
  DataType = "process-network"
  Conditions = [ """"EventId":5156""", """The Windows Filtering Platform has permitted a connection""", """"MachineName":""", """"TimeCreated":""" ]
  Fields = ${WinParserTemplates.windows-kinesis-firehose.Fields} [
    """({event_name}The Windows Filtering Platform has permitted a connection)""",
    """Process ID:\s{0,100}({pid}\d{1,100})""",
    """Application Name:\s{0,100}({process}({directory}[\w:]*[^:]+)[\\\/]({process_name}[^:]+?))\s{0,100}Network Information:""",
    """Direction:\s{0,100}({direction}Inbound).*Source Address:\s{0,100}(::ffff:)?({dest_ip}[a-fA-F:\d.]{1,2000}?)\s{0,100}Source Port:\s{0,100}({dest_port}\d{0,100})\s{0,100}Destination Address:\s{0,100}(::ffff:)?({src_ip}[a-fA-F:\d.]{1,2000}?)\s{0,100}Destination Port:\s{0,100}({src_port}\d{0,100})""",
    """Direction:\s{0,100}({direction}Outbound).*Source Address:\s{0,100}(::ffff:)?({src_ip}[a-fA-F:\d.]{1,2000}?)\s{0,100}Source Port:\s{0,100}({src_port}\d{0,100})\s{0,100}Destination Address:\s{0,100}(::ffff:)?({dest_ip}[a-fA-F:\d.]{1,2000}?)\s{0,100}Destination Port:\s{0,100}({dest_port}\d{0,100})"""
    """Protocol:\s{0,100}({ms_protocol_num}\d{0,100})""",
    """Layer Name:\s{0,100}({layer_name}[^\s]{0,2000})""",    
  ]
  DupFields = [ "host->local_asset" ] 

windows-kinesis-firehose = {
  Vendor = Microsoft
  Product = Windows
  Lms = Kinesis Firehose
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Fields = [
    """"EventId":({event_code}\d{1,5})"""
    """"MachineName":"({host}[^"]{1,2000})"""",
    """"TimeCreated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""
  
}
```