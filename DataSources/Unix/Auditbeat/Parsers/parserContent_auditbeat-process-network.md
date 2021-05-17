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
    """"host":.+?"name":"({host}[^"]{1,2000})"""",
    """"destination":.+?"ip":"({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"source".+?"ip":"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"process":.+?"name":"({process_name}[^"]{1,2000})"""",
    """"process".+?"executable":"({process}(({process_directory}[^"]{0,2000}?)\/)?[^"\\\/]{0,2000}?)"""",
    """"source":.+?"port":({src_port}\d{1,100})""",
    """"destination":.+?"port":({dest_port}\d{1,100})""",
    """"network":.+?"direction":"(unknown|({direction}[^"]{1,2000}))"""",
    """"network":.+?"bytes":({bytes}\d{1,100})""",
    """"domain":"({domain}[^"]{1,2000})"""",
    """"user":\{.+?name":"({user}[^"]{1,2000})"""",
    """"process":.+?"pid":({pid}\d{1,100})""",
    """"complete":({outcome}[^,}]{1,2000})""",
    """"action":"({action}[^"]{1,2000})""""
  ]
  DupFields = ["action->event_name"]
}
```