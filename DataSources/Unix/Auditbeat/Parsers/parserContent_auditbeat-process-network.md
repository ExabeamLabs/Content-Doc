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
    """timestamp":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)"""",
    """"host":.+?"name":"({host}[^"]+)"""",
    """"destination":.+?"ip":"({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"source".+?"ip":"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"process":.+?"name":"({process_name}[^"]+)"""",
    """"process".+?"executable":"({process}(({process_directory}[^"]*?)\/)?[^"\\\/]*?)"""",
    """"source":.+?"port":({src_port}\d{1,100})""",
    """"destination":.+?"port":({dest_port}\d{1,100})""",
    """"network":.+?"direction":"(unknown|({direction}[^"]+))"""",
    """"network":.+?"bytes":({bytes}\d{1,100})""",
    """"domain":"({domain}[^"]+)"""",
    """"user":\{.+?name":"({user}[^"]+)"""",
    """"process":.+?"pid":({pid}\d{1,100})""",
    """"complete":({outcome}[^,}]+)""",
    """"action":"({action}[^"]+)""""
  ]
  DupFields = ["action->event_name"]
}
```