#### Parser Content
```Java
{
Name = json-4768-1
  DataType = "windows-4768"
  Conditions = [ """"event-id":4768""", """"message":"A Kerberos authentication ticket (TGT) was requested""", """"user":""" ]
  Fields = ${WinParserTemplates.json-windows-events.Fields}[
    """"ticket-options":"({ticket_options}[^"]+)""",
    """"ticket-encryption-type":"({ticket_encryption_type}[^"]+)""",
  ]
  DupFields = ["host->dest_host"]
}
json-windows-events = {
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """"@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """"service":".+?","host":"({host}[^"]+)""",
    """"host":"({host}[^"]+)","authentication""",
    """"host":"({host}[^"]+)","service":"""",
    """"host":"({host}[^"]+)","ad"""",
    """"host":"({host}[^"]+)","index"""",
    """"user":\{[^\}]*?"uid":"({user}[^"@]+)""",
    """"country_code2":"({src_external_country}[^"]+)""",
    """"domain":"({domain}[^"]+)""",
    """"source":\{([^\}]*?\{([^\}]*?\{[^\{\}]*?\})*[^\}]*?\})*[^\}]*?"host":"({src_host}[^"]+)""",
    """"source":\{([^\}]*?\{([^\}]*?\{[^\{\}]*?\})*[^\}]*?\})*[^\}]*?"ipv4":"({src_ip}[a-fA-F\d.:]+)""",
    """"destination":\{([^\}]*?\{([^\}]*?\{[^\{\}]*?\})*[^\}]*?\})*[^\}]*?"host":"({dest_host}[^"]+)""",
    """"destination":\{([^\}]*?\{([^\}]*?\{[^\{\}]*?\})*[^\}]*?\})*[^\}]*?"ipv4":"({dest_ip}[a-fA-F\d.:]+)""",
    """"logon-type":({logon_type}\d{1,100})""",
    """"logon-id":"({logon_id}[^"]+)""",
    """"event-type":"({outcome}[^"]+)""",
    """"event-id":({event_code}\d{1,100})""",
    """"message":"({event_name}[^"]+)""",
    """"user-sid":"({user_sid}[^"]+)""",
    """"status":"({result_code}[^"]+)""",
    """"service-name":"({dest_host}[^"]+\$)""",
    """"service-name":"({service_name}[^"]+)"""
  ]

```