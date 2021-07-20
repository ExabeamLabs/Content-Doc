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
    """"@timestamp":"({time}[^"]{1,2000})""",
    """"name_map":\{.*?"uid":"(|({user}[^"]{1,2000}))"""",
    """"user":\{.*?"uid":"({user_id}\d{1,100})"""",
    """"pid":"({pid}\d{1,100})""",
    """"process":\{.*?"exe":"(|({command_line}({directory}[^"]{1,2000}\/).*?))"""",
    """"data":\{.*?"acct":"(|({account}[^"]{1,2000}))"""",
    """"host":\{.*?"name":"(|({host}[^"]{1,2000}))""""
  ]
  DupFields = [ "host->dest_host", "pid->process_id" ]
}
```