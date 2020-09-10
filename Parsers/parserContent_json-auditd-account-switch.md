#### Parser Content
```Java
{
Name = json-auditd-account-switch
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "unix-account-switch"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [""""type":"user_start"""", """PAM:session_open""",""""result":"success""""]
  Fields = [
    """"@timestamp":"({time}[^"]+)""",
    """"name_map":\{.*?"uid":"(|({user}[^"]+))"""",
    """"user":\{.*?"uid":"({user_id}\d+)"""",
    """"pid":"({pid}\d+)""",
    """"process":\{.*?"exe":"(|({command_line}({directory}[^"]+\/).*?))"""",
    """"data":\{.*?"acct":"(|({account}[^"]+))"""",
    """"host":\{.*?"name":"(|({host}[^"]+))""""
  ]
  DupFields = [ "host->dest_host", "pid->process_id" ]
}
```