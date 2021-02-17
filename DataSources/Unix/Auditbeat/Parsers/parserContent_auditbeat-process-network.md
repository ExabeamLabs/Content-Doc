#### Parser Content
```Java
{
Name = auditbeat-process-network
  Vendor = Unix
  Product = Auditbeat
  Lms = Direct
  DataType = "process-network"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [""""auditbeat"""",""""action":"network_flow"""",""""process":""",""""pid":"""]
  Fields = [
    """timestamp":"({time}\d+-\d+-\d+T\d+:\d+:\d+\.\d+Z)"""",
    """"host":.+?"name":"({host}[^"]+)"""",
    """"destination":.+?"ip":"({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"source".+?"ip":"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"process":.+?"name":"({process_name}[^"]+)"""",
    """"process".+?"executable":"({process}(({process_directory}[^"]*?)\/)?[^"\\\/]*?)"""",
    """"source":.+?"port":({src_port}\d+)""",
    """"destination":.+?"port":({dest_port}\d+)""",
    """"network":.+?"direction":"(unknown|({direction}[^"]+))"""",
    """"network":.+?"bytes":({bytes}\d+)""",
    """"domain":"({domain}[^"]+)"""",
    """"user":\{.+?name":"({user}[^"]+)"""",
    """"process":.+?"pid":({pid}\d+)""",
    """"complete":({outcome}[^,}]+)""",
    """"action":"({action}[^"]+)""""
  ]
  DupFields = ["action->event_name"]
}
```